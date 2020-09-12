#pragma once
#include <Windows.h>

#define IOCTL_WRITE_WHAT_WHERE 2236427

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
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Modules[1]; // ntoskrnl is the first entry
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

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
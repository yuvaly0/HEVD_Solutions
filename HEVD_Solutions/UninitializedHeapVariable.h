#pragma once
#include <Windows.h>

#define IOCTL_UNINITIALIZED_HEAP_VARIABLE 2236467
#define CONVERT_TRADEOFF 0x18
#define ALLOCATION_KERNEL_SIZE 0xf0 - CONVERT_TRADEOFF
#define MAXIMUM_LAL_CHUNKS 256

VOID helloWorld();
VOID AllocateEventObjects();
VOID GetObjectName(UCHAR eventName[], ULONG_PTR payload);
VOID freeEventObject();
VOID WaitForLookAsideInit();

std::vector<HANDLE> eventHandles = {};
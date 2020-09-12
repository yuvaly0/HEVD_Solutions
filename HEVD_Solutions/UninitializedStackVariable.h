#pragma once

#define IOCTL_UNINTIALIZED_STACK_VARIABLE 2236463

typedef NTSTATUS(WINAPI* pNtMapUserPhysicalPages)(
	__in PVOID VirtualAddress,
	__in ULONG_PTR NumberOfPages,
	__in PULONG_PTR UserPfnArray
	);
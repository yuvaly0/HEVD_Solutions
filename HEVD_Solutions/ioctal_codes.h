#pragma once
#include <winioctl.h>
#include <winnt.h>

#define IOCTL_STACK_OVERFLOW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS);
#define IOCTL_INTEGER_OVERFLOW 2236455
#define IOCTL_WRITE_WHAT_WHERE 2236427
#define IOCTL_NULL_POINTER_DEREFERENCE 2236459
#define IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED 2236435
#define IOCTL_USE_UAF_NON_PAGED 2236439
#define IOCTL_FREE_UAF_NON_PAGED 2236443
#define IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED 2236447
#define IOCTL_NON_PAGED_POOL_OVERFLOW 2236431
#define IOCTL_UNINTIALIZED_STACK_VARIABLE 2236463
#define IOCTL_UNINITIALIZED_HEAP_VARIABLE 2236467
#define IOCTL_DOUBLE_FETCH 2236471
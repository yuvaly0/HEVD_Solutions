#pragma once
#include <Windows.h>

#define IOCTL_DOUBLE_FETCH 2236471
#define OVERFLOW_OFFSET 2080

DWORD WINAPI SizeChaingingThread(LPVOID userValue);
DWORD WINAPI IoctlThread(LPVOID userValue);
VOID JumpHere();

struct UserDoubleFetch {
	PCHAR buffer;
	SIZE_T size;
};

typedef struct UserDoubleFetch UserDoubleFetch;

HANDLE hHevd;
BOOL shouldContinue = TRUE;
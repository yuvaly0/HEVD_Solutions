#pragma once
#include <Windows.h>

#define OVERFLOW_OFFSET 2080

DWORD WINAPI SizeChaingingThread(LPVOID userValue);
DWORD WINAPI IoctlThread(LPVOID userValue);
VOID JumpHere();

struct UserDoubleFetch {
	PCHAR buffer;
	SIZE_T size;
};

typedef struct UserDoubleFetch UserDoubleFetch;
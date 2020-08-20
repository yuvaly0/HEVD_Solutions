#include <Windows.h>
#include <iostream>

#include "ioctal_codes.h"
#include "utils.h"
#include "Solutions.h"

#define MAX_CHOICE 6
#define MIN_CHOICE 1

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
	
	printMenu();
	int choice = GetUserChoice();
	if (choice > MAX_CHOICE || choice < MIN_CHOICE) {
		return 1;
	}

	Solutions* solutions = new Solutions(hDeviceHandle);
	return solutions->TriggerExploit(choice);
}
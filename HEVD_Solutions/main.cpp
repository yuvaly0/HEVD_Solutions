#include <Windows.h>
#include <iostream>
#include <memory>

#include "ioctal_codes.h"
#include "utils.h"
#include "Solutions.h"

#define MAX_CHOICE 9
#define MIN_CHOICE 1

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
		std::cout << "[-] ERROR: invalid handle" << std::endl;
		return 1;
	}
	
	print_menu();
	const int choice = get_user_choice();
	if (choice > MAX_CHOICE || choice < MIN_CHOICE) {
		std::cout << "bad choice" << std::endl;
		return 1;
	}

	auto solutions = std::make_unique<Solutions>(hDeviceHandle);
	return solutions->TriggerExploit(choice);
}
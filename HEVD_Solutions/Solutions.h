#include <Windows.h>

class Solutions {
	public:
		Solutions(HANDLE hDeviceHandle) {
			_hDeviceHandle = hDeviceHandle;
		}

		~Solutions() {
			CloseHandle(_hDeviceHandle);
		}

		NTSTATUS TriggerStackBufferOverflow();
		NTSTATUS TriggerIntegerOverflow();
		NTSTATUS TriggerWriteWhatWhere();
		NTSTATUS TriggerNullPointerDereference();
		NTSTATUS TriggerUAF();
		NTSTATUS TriggerNonPagedPoolOverflow();
		NTSTATUS TriggerUninitializedStackVariable();
		NTSTATUS TriggerUninitializedHeapVariable();
		NTSTATUS TriggerDoubleFetch();

		NTSTATUS TriggerExploit(int choice);

	private:
		HANDLE _hDeviceHandle;
};
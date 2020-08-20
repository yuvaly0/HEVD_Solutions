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

	private:
		HANDLE _hDeviceHandle;
};
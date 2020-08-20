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
		NTSTATUS TriggerExploit(int choice) {
			switch (choice) {
			case 1:
				return this->TriggerStackBufferOverflow();
			case 2:
				return this->TriggerIntegerOverflow();
			case 3:
				return this->TriggerWriteWhatWhere();
			case 4:
				return this->TriggerNullPointerDereference();
			case 5:
				return this->TriggerUAF();
			case 6: 
				return this->TriggerNonPagedPoolOverflow();
			}
		}

	private:
		HANDLE _hDeviceHandle;
};
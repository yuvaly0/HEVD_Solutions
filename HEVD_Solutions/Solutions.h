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
			case 7:
				return this->TriggerUninitializedStackVariable();
			case 8:
				return this->TriggerUninitializedHeapVariable();
			case 9:
				return this->TriggerDoubleFetch();
			}
		}

	private:
		HANDLE _hDeviceHandle;
};
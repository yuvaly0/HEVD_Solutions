#include <Windows.h>

class Solutions {
	public:
		Solutions(HANDLE hDeviceHandle) {
			_hDeviceHandle = hDeviceHandle;
		}

		~Solutions() {
			CloseHandle(_hDeviceHandle);
		}

		DWORD TriggerStackBufferOverflow();
		DWORD TriggerIntegerOverflow();
		DWORD TriggerWriteWhatWhere();
		DWORD TriggerNullPointerDereference();

	private:
		HANDLE _hDeviceHandle;
};
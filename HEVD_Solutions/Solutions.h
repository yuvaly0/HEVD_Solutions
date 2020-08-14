#include <Windows.h>

class Solutions {
	public:
		Solutions(HANDLE hDeviceHandle) {
			_hDeviceHandle = hDeviceHandle;
		}

		DWORD TriggerStackBufferOverflow();
		DWORD TriggerIntegerOverflow();
		DWORD TriggerWriteWhatWhere();

	private:
		HANDLE _hDeviceHandle;
};
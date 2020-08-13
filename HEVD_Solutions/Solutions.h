#include <Windows.h>

class Solutions {
	public:
		Solutions(HANDLE hDeviceHandle) {
			_hDeviceHandle = hDeviceHandle;
		}

		DWORD TriggerStackBufferOverflow();
		DWORD TriggerIntegerOverflow();

	private:
		HANDLE _hDeviceHandle;
};
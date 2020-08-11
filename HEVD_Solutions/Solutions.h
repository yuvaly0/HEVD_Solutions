#include <Windows.h>

class Solutions {
	public:
		Solutions(HANDLE hDeviceHandle) {
			_hDeviceHandle = hDeviceHandle;
		}

		DWORD TriggerStackBufferOverflow();

	private:
		HANDLE _hDeviceHandle;
};
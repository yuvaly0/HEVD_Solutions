#include "Solutions.h"

NTSTATUS Solutions::TriggerExploit(int choice) {
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
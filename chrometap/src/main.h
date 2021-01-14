#pragma once
#include <ntstatus.h>
#include <winternl.h>
#include <tlhelp32.h>
#pragma intrinsic(memcpy,strcpy,strcmp,strlen)

WINBASEAPI void *__cdecl MSVCRT$malloc(size_t size);
WINBASEAPI void *__cdecl MSVCRT$memset(void *str, int c, size_t n);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcsstr(wchar_t* wcs1, const wchar_t* wcs2);
WINBASEAPI int __cdecl MSVCRT$wcscmp(const wchar_t* wcs1, const wchar_t* wcs2);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void *dest, const void * src, size_t n);

WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI BOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI BOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

typedef LONG KPRIORITY;

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

EXTERN_C NTSTATUS NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);
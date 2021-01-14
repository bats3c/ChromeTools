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

// typedef HANDLE (WINAPI * OpenProcess_) NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
// 	IN OUT PVOID SystemInformation,
// 	IN ULONG SystemInformationLength,
// 	OUT PULONG ReturnLength OPTIONAL);
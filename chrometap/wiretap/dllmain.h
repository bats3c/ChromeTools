#pragma once
#include <windows.h>

#define LOGFILE_PATH "C:\\windows\\temp\\chromecrash.log"
#define READFILE_HOOKED 0xC001C0DED00D

typedef BOOL(WINAPI* FUNC_ReadFile)(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
);
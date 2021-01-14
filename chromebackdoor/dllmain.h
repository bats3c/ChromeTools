#pragma once
#include <windows.h>

#define WRITEFILE_HOOKED 0xC001C0DED00D

typedef BOOL(WINAPI* FUNC_WriteFile)(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
);

typedef BOOL(WINAPI* FUNC_CryptStringToBinaryA)(
	LPCSTR pszString,
	DWORD  cchString,
	DWORD  dwFlags,
	BYTE   *pbBinary,
	DWORD  *pcbBinary,
	DWORD  *pdwSkip,
	DWORD  *pdwFlags
);
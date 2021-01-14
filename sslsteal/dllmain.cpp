// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <stdio.h>
#include <windows.h>
#include <tdh.h>
#include <psapi.h>
#include <evntcons.h>
#include <tlhelp32.h>

#define PATTERN "\x41\x56\x56\x57\x55\x53\x48\x83\xEC\x40\x45\x89\xC6\x48\x89\xD7\x48\x89\xCB\x48"

LPVOID lpCallbackOffset;
CHAR   OriginalBytes[50] = {};

VOID HookSSLWrite();
typedef int(WINAPI* _SSL_write) (void* ssl, const void* buf, int num);

int DoOriginalSSLWrite(void* ssl, const void* buf, int num)
{

	DWORD dwOldProtect;

	VirtualProtect(lpCallbackOffset, sizeof(OriginalBytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(lpCallbackOffset, OriginalBytes, sizeof(OriginalBytes));
	VirtualProtect(lpCallbackOffset, sizeof(OriginalBytes), dwOldProtect, &dwOldProtect);

	_SSL_write EtwEventCallback = (_SSL_write)lpCallbackOffset;

    int ret = EtwEventCallback(ssl, buf, num);

	HookSSLWrite();

	return ret;
}

int SSL_write(void* ssl, void* buf, int num) {
	MessageBoxA(NULL, (char*)buf, "SSL_write", 0);

	return DoOriginalSSLWrite(ssl, buf, num);
}

VOID HookSSLWrite()
{
	DWORD oldProtect, oldOldProtect;

	unsigned char boing[] = { 0x49, 0xbb, 0xde, 0xad, 0xc0, 0xde, 0xde, 0xad, 0xc0, 0xde, 0x41, 0xff, 0xe3 };

	*(void**)(boing + 2) = &SSL_write;

	VirtualProtect(lpCallbackOffset, 13, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(lpCallbackOffset, boing, sizeof(boing));
	VirtualProtect(lpCallbackOffset, 13, oldProtect, &oldOldProtect);

	return;
}

BOOL DoHook()
{
	DWORD_PTR dwBase;
	DWORD i, dwSizeNeeded;
	CHAR cStringBuffer[200];
	HMODULE hModules[102400];
	TCHAR   szModule[MAX_PATH];
	DWORD oldProtect, oldOldProtect;

	if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &dwSizeNeeded))
	{
		for (int i = 0; i < (dwSizeNeeded / sizeof(HMODULE)); i++)
		{
			ZeroMemory((PVOID)szModule, MAX_PATH);

			if (GetModuleBaseNameA(GetCurrentProcess(), hModules[i], (LPSTR)szModule, sizeof(szModule) / sizeof(TCHAR)))
			{
				if (!strcmp("chrome.dll", (const char*)szModule))
				{
					dwBase = (DWORD_PTR)hModules[i];
				}
			}
		}
	}

	sprintf_s(cStringBuffer, "[i] Base Address: 0x%llx\n", dwBase);
	MessageBoxA(NULL, cStringBuffer, "Hook", 0);
	memset(cStringBuffer, '\0', strlen(cStringBuffer));

	for (i = 0; i < 0xffffffff; i++)
	{

		if (!memcmp((PVOID)(dwBase + i), (unsigned char*)PATTERN, strlen(PATTERN)))
		{
			lpCallbackOffset = (LPVOID)(dwBase + i);

			sprintf(cStringBuffer, "[i] Offset: 0x%llx\n", lpCallbackOffset);
			MessageBoxA(NULL, cStringBuffer, "Hook", 0);
			memset(cStringBuffer, '\0', strlen(cStringBuffer));

			memcpy(OriginalBytes, lpCallbackOffset, 50);

			HookSSLWrite();

			return TRUE;
		}
	}

	return FALSE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(NULL, L"Injected", L"hello", 0);
        DoHook();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


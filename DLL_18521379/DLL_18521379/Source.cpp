#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string.h>
#include <stdlib.h>
#include <fstream>

#pragma region Globals
char szDllPath[] = "C:\\Users\\THAIDUI\\source\\repos\\64test\\x64\\Debug\\64test.dll";
char szAttachProgram[] = "opera.exe";
DWORD dwMainProcessId = 0x00;

DWORD Win32ReturnProcessId(PCHAR pProcessName)
{
	HANDLE hToolHelper = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0x00);
	PROCESSENTRY32 p32ProcessEntry = { 0 };
	p32ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	if (hToolHelper != NULL)
	{
		if (Process32First(hToolHelper, &p32ProcessEntry))
		{
			do
			{
				if (!strcmp(p32ProcessEntry.szExeFile, pProcessName))
				{
					dwMainProcessId = p32ProcessEntry.th32ProcessID;
					CloseHandle(hToolHelper);
					return dwMainProcessId;
				}
			} while (Process32Next(hToolHelper, &p32ProcessEntry));
		}
		else
		{
			throw std::runtime_error("Process32First()");
		}
	}
	CloseHandle(hToolHelper);
	return dwMainProcessId;
}

BOOL Win32InjectDllToProcess(DWORD dwProcessId, PCHAR pcPathToDll)	
{
	char szFullDllPathName[MAX_PATH];

	if (GetFullPathName(pcPathToDll, MAX_PATH, szFullDllPathName, NULL))
	{
		std::cout << "DLL Path: " << szFullDllPathName << '\n';
	}

	HANDLE hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcessHandle)
	{
		LPVOID lpLoadLibAddress = reinterpret_cast<LPVOID>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
		if (lpLoadLibAddress == NULL)
		{
			throw std::runtime_error("GetProcAddress");
		}
		LPVOID lpLoadLocation = VirtualAllocEx(hProcessHandle, 0x00, strlen(pcPathToDll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (lpLoadLocation == NULL)
		{
			throw std::runtime_error("VirtualAllocEx()");
		}

		if (WriteProcessMemory(hProcessHandle, lpLoadLocation, pcPathToDll, strlen(szFullDllPathName) + 1, NULL))
		{
			std::cout << "Memory Written at: 0x" << std::hex << lpLoadLocation << '\n';
		}
		else
		{
			throw std::runtime_error("WriteProcessMemory()");
		}

		HANDLE hRemotethreader = CreateRemoteThread(hProcessHandle, NULL, 0x00, (LPTHREAD_START_ROUTINE)lpLoadLibAddress, lpLoadLocation, NULL, NULL);
		WaitForSingleObject(hRemotethreader, INFINITE);
		VirtualFreeEx(hProcessHandle, lpLoadLocation, strlen(szFullDllPathName) + 1, MEM_RELEASE);

		if ((!CloseHandle(hProcessHandle)) && (!CloseHandle(hRemotethreader)))
		{
			throw std::runtime_error(reinterpret_cast<PCHAR>(GetLastError()));
			return FALSE;
		}
		return TRUE;
	}
}

int main(void)
{
	dwMainProcessId = Win32ReturnProcessId(szAttachProgram);
	if (dwMainProcessId)
	{
		std::cout << dwMainProcessId << '\n';
		Win32InjectDllToProcess(dwMainProcessId, szDllPath);
	}
	else
	{
		return -1;
	}
	system("PAUSE");
}
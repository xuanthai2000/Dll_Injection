#include <Windows.h>

VOID ExeWorkerRoutine()
{
	MessageBoxA(0, "DLL INJECTED!", "Success", MB_OK);
}

BOOL __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);

		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ExeWorkerRoutine, NULL, 0, NULL);
	}

	return TRUE;
}
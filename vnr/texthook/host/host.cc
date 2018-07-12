// host.cc
// 8/24/2013 jichi
// Branch IHF/main.cpp, rev 111
// 8/24/2013 TODO: Clean up this file

//#ifdef _MSC_VER
//# pragma warning(disable:4800) // C4800: forcing value to bool (performance warning)
//#endif // _MSC_VER

//#include "customfilter.h"
#include "growl.h"
#include "host.h"
#include "host_p.h"
#include "settings.h"
#include "vnrhook/include/const.h"
#include "vnrhook/include/defs.h"
#include "vnrhook/include/types.h"
#include "ithsys/ithsys.h"
#include <commctrl.h>
#include <string>
#include "extensions/Extensions.h"

#define DEBUG "vnrhost/host.cc"

namespace 
{ // unnamed

	CRITICAL_SECTION hostCs;
	HANDLE preventDuplicationMutex; // jichi 9/28/2013: used to guard pipe
	HANDLE hookMutex;  // jichi 9/28/2013: used to guard hook modification
} // unnamed namespace

//extern LPWSTR current_dir;
extern CRITICAL_SECTION detachCs;

Settings *settings;
HWND dummyWindow;
BOOL running;

#define ITH_SYNC_HOOK MutexLocker locker(::hookMutex)

namespace 
{ // unnamed

	void GetDebugPrivileges()
	{ // Artikash 5/19/2018: Is it just me or is this function 100% superfluous?
		HANDLE processToken;
		TOKEN_PRIVILEGES Privileges = {1, {0x14, 0, SE_PRIVILEGE_ENABLED}};

		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken);
		AdjustTokenPrivileges(processToken, FALSE, &Privileges, 0, nullptr, nullptr);
		CloseHandle(processToken);
	}

} // unnamed namespace

void CreateNewPipe();

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID unused)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hinstDLL);
		InitializeCriticalSection(&::hostCs);
		GetDebugPrivileges();
		// jichi 12/20/2013: Since I already have a GUI, I don't have to InitCommonControls()
		// Used by timers.
		// InitCommonControls();
		// jichi 8/24/2013: Create hidden window so that ITH can access timer and events
		dummyWindow = CreateWindowW(L"Button", L"InternalWindow", 0, 0, 0, 0, 0, 0, 0, hinstDLL, 0);
		break;
	case DLL_PROCESS_DETACH:
		if (::running)
			CloseHost();
		DeleteCriticalSection(&::hostCs);
		DestroyWindow(dummyWindow);
		break;
	default:
		break;
	}
	return true;
}

IHFSERVICE bool IHFAPI OpenHost()
{
	bool success;
	EnterCriticalSection(&::hostCs);

	preventDuplicationMutex = CreateMutexW(nullptr, TRUE, ITH_SERVER_MUTEX);
	if (GetLastError() == ERROR_ALREADY_EXISTS || ::running)
	{
		GROWL_WARN(L"I am sorry that this game is attached by some other VNR ><\nPlease restart the game and try again!");
		success = false;
	}
	else
	{
		LoadExtensions();
		::running = true;
		::settings = new Settings;
		::man = new HookManager;
		InitializeCriticalSection(&detachCs);
		::hookMutex = CreateMutexW(nullptr, FALSE, ITH_SERVER_HOOK_MUTEX);
		success = true;
	}
	LeaveCriticalSection(&::hostCs);
	return success;
}

IHFSERVICE void IHFAPI StartHost()
{
	CreateNewPipe();
}

IHFSERVICE void IHFAPI CloseHost()
{
	EnterCriticalSection(&::hostCs);
	if (::running)
	{
		::running = false;
		delete man;
		delete settings;
		CloseHandle(::hookMutex);
		CloseHandle(preventDuplicationMutex);
		DeleteCriticalSection(&detachCs);
	}
	LeaveCriticalSection(&::hostCs);
}

IHFSERVICE bool IHFAPI InjectProcessById(DWORD processId, DWORD timeout)
{
	bool success = true;

	if (processId == GetCurrentProcessId())
	{
		success = false;
	}

	CloseHandle(CreateMutexW(nullptr, FALSE, (ITH_HOOKMAN_MUTEX_ + std::to_wstring(processId)).c_str()));
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		man->AddConsoleOutput(L"already locked");
		success = false;
	}

	HMODULE textHooker = LoadLibraryExW(ITH_DLL, nullptr, DONT_RESOLVE_DLL_REFERENCES);
	if (textHooker == nullptr)
	{
		success = false;
	}
	wchar_t textHookerPath[MAX_PATH];
	unsigned int textHookerPathSize = GetModuleFileNameW(textHooker, textHookerPath, MAX_PATH) * 2 + 2;
	FreeLibrary(textHooker);

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (processHandle == INVALID_HANDLE_VALUE || processHandle == nullptr)
	{
		success = false;
	}

	LPTHREAD_START_ROUTINE loadLibraryStartRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");

	if (success)
	{
		if (LPVOID remoteData = VirtualAllocEx(processHandle, nullptr, textHookerPathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
		{
			if (WriteProcessMemory(processHandle, remoteData, textHookerPath, textHookerPathSize, nullptr))
			{
				if (HANDLE thread = CreateRemoteThread(processHandle, nullptr, 0, loadLibraryStartRoutine, remoteData, 0, nullptr))
				{
					WaitForSingleObject(thread, timeout);
					CloseHandle(thread);
				}
				else
				{
					success = false;
				}
			}
			else
			{
				success = false;
			}
			VirtualFreeEx(processHandle, remoteData, textHookerPathSize, MEM_RELEASE);
		}
		else
		{
			success = false;
		}
	}

	if (!success)
	{
		man->AddConsoleOutput(L"error: could not inject");
	}

	CloseHandle(processHandle);
	return success;
}

IHFSERVICE bool IHFAPI DetachProcessById(DWORD processId)
{
	DWORD command = HOST_COMMAND_DETACH;
	return WriteFile(man->GetCommandPipe(processId), &command, sizeof(command), nullptr, nullptr);
}

IHFSERVICE void IHFAPI GetHostHookManager(HookManager** hookman)
{
	if (::running)
	{
		*hookman = man;
	}
}

IHFSERVICE void IHFAPI GetHostSettings(Settings **p)
{
	if (::running)
	{
		*p = settings;
	}
}

IHFSERVICE DWORD IHFAPI InsertHook(DWORD pid, HookParam *hp, std::string name)
{
  HANDLE commandPipe = man->GetCommandPipe(pid);
  if (commandPipe == nullptr)
    return -1;

  BYTE buffer[PIPE_BUFFER_SIZE] = {};
  *(DWORD*)buffer = HOST_COMMAND_NEW_HOOK;
  memcpy(buffer + 4, hp, sizeof(HookParam));
  if (name.size()) strcpy((char*)buffer + 4 + sizeof(HookParam), name.c_str());

  WriteFile(commandPipe, buffer, 4 + sizeof(HookParam) + name.size(), nullptr, nullptr);
  return 0;
}

IHFSERVICE DWORD IHFAPI Host_RemoveHook(DWORD pid, DWORD addr)
{
	HANDLE commandPipe = man->GetCommandPipe(pid);
	if (commandPipe == nullptr)
		return -1;
    
	HANDLE hookRemovalEvent = CreateEventW(nullptr, TRUE, FALSE, ITH_REMOVEHOOK_EVENT);
	BYTE buffer[8];
	*(DWORD*)buffer = HOST_COMMAND_REMOVE_HOOK;
	*(DWORD*)(buffer + 4) = addr;
  
  WriteFile(commandPipe, buffer, 8, nullptr, nullptr);
  WaitForSingleObject(hookRemovalEvent, 1000);
  CloseHandle(hookRemovalEvent);
  man->RemoveSingleHook(pid, addr);
  return 0;
}

// EOF

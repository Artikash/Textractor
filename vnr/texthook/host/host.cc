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
#include "ccutil/ccmacro.h"
#include <commctrl.h>

#define DEBUG "vnrhost/host.cc"
#include "sakurakit/skdebug.h"

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

#define ITH_SYNC_HOOK   IthMutexLocker locker(::hookMutex)

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
		IthInitSystemService();
		GetDebugPrivileges();
		// jichi 12/20/2013: Since I already have a GUI, I don't have to InitCommonControls()
		// Used by timers.
		InitCommonControls();
		// jichi 8/24/2013: Create hidden window so that ITH can access timer and events
		dummyWindow = CreateWindowW(L"Button", L"InternalWindow", 0, 0, 0, 0, 0, 0, 0, hinstDLL, 0);
		break;
	case DLL_PROCESS_DETACH:
		if (::running)
			CloseHost();
		DeleteCriticalSection(&::hostCs);
		IthCloseSystemService();
		DestroyWindow(dummyWindow);
		break;
	default:
		break;
	}
	return true;
}

enum { IHS_SIZE = 0x80 };
enum { IHS_BUFF_SIZE = IHS_SIZE - sizeof(HookParam) };

struct InsertHookStruct
{
	SendParam sp;
	BYTE name_buffer[IHS_SIZE];
};

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

	CloseHandle(CreateMutexW(nullptr, FALSE, CONCAT_STR_NUM(ITH_HOOKMAN_MUTEX_, processId)));
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
	ITH_SYNC_HOOK;
	DWORD command = HOST_COMMAND_DETACH;
	return WriteFile(man->GetCmdHandleByPID(processId), &command, sizeof(command), nullptr, nullptr);
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

// Artikash 5/11/2018: I don't understand the following operations, so I'm making minimal changes in cleanup

IHFSERVICE DWORD IHFAPI Host_InsertHook(DWORD pid, HookParam *hp, LPCSTR name)
{
  ITH_SYNC_HOOK;

  HANDLE hCmd = man->GetCmdHandleByPID(pid);
  if (hCmd == 0)
    return -1;

  InsertHookStruct s;
  s.sp.type = HOST_COMMAND_NEW_HOOK;
  s.sp.hp = *hp;
  size_t len;
  if (name)
    len = ::strlen(name);
  else
    len = 0;
  if (len) {
    if (len >= IHS_BUFF_SIZE) len = IHS_BUFF_SIZE - 1;
    memcpy(s.name_buffer, name, len);
  }
  s.name_buffer[len] = 0;
  IO_STATUS_BLOCK ios;
  DWORD unused;
  WriteFile(hCmd, &s, IHS_SIZE, &unused, nullptr);

  //memcpy(&sp.hp,hp,sizeof(HookParam));
  //cmdq->AddRequest(sp, pid);
  return 0;
}

IHFSERVICE DWORD IHFAPI Host_RemoveHook(DWORD pid, DWORD addr)
{
  ITH_SYNC_HOOK;

  HANDLE hRemoved,hCmd;
  hCmd = GetCmdHandleByPID(pid);
  if (hCmd == 0)
    return -1;
  hRemoved = CreateEventW(nullptr, TRUE, FALSE, ITH_REMOVEHOOK_EVENT);
  SendParam sp = {};
  IO_STATUS_BLOCK ios;
  sp.type = HOST_COMMAND_REMOVE_HOOK;
  sp.hp.address = addr;
  //cmdq -> AddRequest(sp, pid);
  DWORD unused;
  WriteFile(hCmd, &sp, sizeof(sp), &unused, nullptr);
  // jichi 10/22/2013: Timeout might crash vnrsrv
  //const LONGLONG timeout = HOOK_TIMEOUT;
  //NtWaitForSingleObject(hRemoved, 0, (PLARGE_INTEGER)&timeout);
  WaitForSingleObject(hRemoved, MAXDWORD);
  CloseHandle(hRemoved);
  man -> RemoveSingleHook(pid, sp.hp.address);
  return 0;
}

// 4/30/2015: Removed as not needed. Going to change to json
IHFSERVICE DWORD IHFAPI Host_AddLink(DWORD from, DWORD to)
{
  man->AddLink(from & 0xffff, to & 0xffff);
  return 0;
}

IHFSERVICE DWORD IHFAPI Host_UnLink(DWORD from)
{
  man->UnLink(from & 0xffff);
  return 0;
}

IHFSERVICE DWORD IHFAPI Host_UnLinkAll(DWORD from)
{
  man->UnLinkAll(from & 0xffff);
  return 0;
}

// EOF

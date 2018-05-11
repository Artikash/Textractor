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

//#define ITH_WINE
//#define ITH_USE_UX_DLLS  IthIsWine()
//#define ITH_USE_XP_DLLS  (IthIsWindowsXp() && !IthIsWine())

#define DEBUG "vnrhost/host.cc"
#include "sakurakit/skdebug.h"

namespace 
{ // unnamed

//enum { HOOK_TIMEOUT = -50000000 }; // in nanoseconds = 5 seconds

	CRITICAL_SECTION hostCs;
	//WCHAR exist[] = ITH_PIPEEXISTS_EVENT;
	//WCHAR mutex[] = L"ITH_RUNNING";
	//WCHAR EngineName[] = ITH_ENGINE_DLL;
	//WCHAR EngineNameXp[] = ITH_ENGINE_XP_DLL;
	//WCHAR DllName[] = ITH_CLIENT_DLL;
	//WCHAR DllNameXp[] = ITH_CLIENT_XP_DLL;
	HANDLE preventDuplicationMutex; // jichi 9/28/2013: used to guard pipe
	HANDLE hookMutex;  // jichi 9/28/2013: used to guard hook modification
} // unnamed namespace

//extern LPWSTR current_dir;
extern CRITICAL_SECTION detachCs;

Settings *settings;
HWND dummyWindow;
HANDLE pipeExistsEvent;
BOOL running;

#define ITH_SYNC_HOOK   IthMutexLocker locker(::hookMutex)

namespace 
{ // unnamed

	void GetDebugPrivileges()
	{
		HANDLE processToken;
		TOKEN_PRIVILEGES Privileges = { 1, {0x14, 0, SE_PRIVILEGE_ENABLED} };

		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken);
		AdjustTokenPrivileges(processToken, FALSE, &Privileges, 0, nullptr, nullptr);
		CloseHandle(processToken);
	}

	bool sendCommand(HANDLE commandPipe, HostCommandType command)
	{
		DWORD unused;
		return commandPipe && WriteFile(commandPipe, &command, sizeof(command), &unused, nullptr);
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
		//Used by timers.
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
	::pipeExistsEvent = CreateEventW(nullptr, TRUE, TRUE, ITH_PIPEEXISTS_EVENT);
}

IHFSERVICE void IHFAPI CloseHost()
{
	EnterCriticalSection(&::hostCs);
	if (::running)
	{
		::running = FALSE;
		ResetEvent(::pipeExistsEvent);
		delete man;
		delete settings;
		CloseHandle(::hookMutex);
		CloseHandle(preventDuplicationMutex);
		CloseHandle(::pipeExistsEvent);
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

	HMODULE textHooker = LoadLibraryExW(L"vnrhook", nullptr, DONT_RESOLVE_DLL_REFERENCES);
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

	void* loadLibraryStartRoutine = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");

	if (success)
	{
		if (LPVOID remoteData = VirtualAllocEx(processHandle, nullptr, textHookerPathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
		{
			if (WriteProcessMemory(processHandle, remoteData, textHookerPath, textHookerPathSize, nullptr))
			{
				if (HANDLE thread = CreateRemoteThread(processHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryStartRoutine, remoteData, 0, nullptr))
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

// jichi 7/16/2014: Test if process is valid before creating remote threads
// See: http://msdn.microsoft.com/en-us/library/ms687032.aspx
static bool isProcessTerminated(HANDLE processHandle)
{
	return WAIT_OBJECT_0 == ::WaitForSingleObject(processHandle, 0);
}

IHFSERVICE bool IHFAPI DetachProcessById(DWORD pid) // Todo: clean this up
{
  ITH_SYNC_HOOK;

  //man->LockHookman();
  ProcessRecord *pr = man->GetProcessRecord(pid);
  HANDLE hCmd = man->GetCmdHandleByPID(pid);
  if (pr == 0 || hCmd == 0)
    return false;
  HANDLE hProc;
  //hProc = pr->process_handle; //This handle may be closed(thus invalid) during the detach process.
  NtDuplicateObject(NtCurrentProcess(), pr->process_handle,
      NtCurrentProcess(), &hProc, 0, 0, DUPLICATE_SAME_ACCESS); // Make a copy of the process handle.
  HANDLE hModule = (HANDLE)pr->module_register;
  if (!hModule) {
    DOUT("process module not found");
    return false;
  }

  // jichi 7/15/2014: Process already closed
  if (isProcessTerminated(hProc)) {
    DOUT("process has terminated");
    return false;
  }

  // jichi 10/19/2014: Disable the second dll
  //engine = pr->engine_register;
  //engine &= ~0xff;

  DOUT("send detach command");
  bool ret = sendCommand(hCmd, HOST_COMMAND_DETACH);

  // jichi 7/15/2014: Process already closed
  //if (isProcessTerminated(hProc)) {
  //  DOUT("process has terminated");
  //  return false;
  //}
  //WinDbg::ejectDll(hModule, 0, hProc); // eject in case module has not loaded yet

  //cmdq->AddRequest(sp, pid);
////#ifdef ITH_WINE // Nt series crash on wine
////  hThread = IthCreateThread(FreeLibrary, engine, hProc);
////#else
//  hThread = IthCreateThread(LdrUnloadDll, engine, hProc);
////#endif // ITH_WINE
//  if (hThread == 0 || hThread == INVALID_HANDLE_VALUE)
//    return FALSE;
//  // jichi 10/22/2013: Timeout might crash vnrsrv
//  //const LONGLONG timeout = HOOK_TIMEOUT;
//  //NtWaitForSingleObject(hThread, 0, (PLARGE_INTEGER)&timeout);
//  NtWaitForSingleObject(hThread, 0, nullptr);
//  NtClose(hThread);
  NtClose(hProc);
  return ret;
}

IHFSERVICE DWORD IHFAPI Host_GetHookManager(HookManager** hookman)
{
  if (::running) {
    *hookman = man;
    return 0;
  }
  else
    return 1;
}

IHFSERVICE bool IHFAPI Host_GetSettings(Settings **p)
{
  if (::running) {
    *p = settings;
    return true;
  }
  else
    return false;
}

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
  NtWriteFile(hCmd, 0,0,0, &ios, &s, IHS_SIZE, 0, 0);

  //memcpy(&sp.hp,hp,sizeof(HookParam));
  //cmdq->AddRequest(sp, pid);
  return 0;
}

IHFSERVICE DWORD IHFAPI Host_ModifyHook(DWORD pid, HookParam *hp)
{
  ITH_SYNC_HOOK;

  HANDLE hCmd = GetCmdHandleByPID(pid);
  if (hCmd == 0)
    return -1;
  HANDLE hModify = IthCreateEvent(ITH_MODIFYHOOK_EVENT);
  SendParam sp;
  sp.type = HOST_COMMAND_MODIFY_HOOK;
  sp.hp = *hp;
  IO_STATUS_BLOCK ios;
  if (NT_SUCCESS(NtWriteFile(hCmd, 0,0,0, &ios, &sp, sizeof(SendParam), 0, 0)))
    // jichi 9/28/2013: no wait timeout
    //const LONGLONG timeout = HOOK_TIMEOUT;
    NtWaitForSingleObject(hModify, 0, nullptr);
  NtClose(hModify);
  man->RemoveSingleHook(pid, sp.hp.address);
  return 0;
}

IHFSERVICE DWORD IHFAPI Host_RemoveHook(DWORD pid, DWORD addr)
{
  ITH_SYNC_HOOK;

  HANDLE hRemoved,hCmd;
  hCmd = GetCmdHandleByPID(pid);
  if (hCmd == 0)
    return -1;
  hRemoved = IthCreateEvent(ITH_REMOVEHOOK_EVENT);
  SendParam sp = {};
  IO_STATUS_BLOCK ios;
  sp.type = HOST_COMMAND_REMOVE_HOOK;
  sp.hp.address = addr;
  //cmdq -> AddRequest(sp, pid);
  NtWriteFile(hCmd, 0,0,0, &ios, &sp, sizeof(SendParam),0,0);
  // jichi 10/22/2013: Timeout might crash vnrsrv
  //const LONGLONG timeout = HOOK_TIMEOUT;
  //NtWaitForSingleObject(hRemoved, 0, (PLARGE_INTEGER)&timeout);
  NtWaitForSingleObject(hRemoved, 0, nullptr);
  NtClose(hRemoved);
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

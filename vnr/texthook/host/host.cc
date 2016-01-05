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
#include "windbg/inject.h"
#include "winmaker/winmaker.h"
#include "ccutil/ccmacro.h"
#include <commctrl.h>

//#define ITH_WINE
//#define ITH_USE_UX_DLLS  IthIsWine()
//#define ITH_USE_XP_DLLS  (IthIsWindowsXp() && !IthIsWine())

#define DEBUG "vnrhost/host.cc"
#include "sakurakit/skdebug.h"

namespace { // unnamed

//enum { HOOK_TIMEOUT = -50000000 }; // in nanoseconds = 5 seconds

CRITICAL_SECTION cs;
//WCHAR exist[] = ITH_PIPEEXISTS_EVENT;
//WCHAR mutex[] = L"ITH_RUNNING";
//WCHAR EngineName[] = ITH_ENGINE_DLL;
//WCHAR EngineNameXp[] = ITH_ENGINE_XP_DLL;
//WCHAR DllName[] = ITH_CLIENT_DLL;
//WCHAR DllNameXp[] = ITH_CLIENT_XP_DLL;
HANDLE hServerMutex; // jichi 9/28/2013: used to guard pipe
HANDLE hHookMutex;  // jichi 9/28/2013: used to guard hook modification
} // unnamed namespace

//extern LPWSTR current_dir;
extern CRITICAL_SECTION detach_cs;

Settings *settings;
HWND hMainWnd;
HANDLE hPipeExist;
BOOL running;

#define ITH_SYNC_HOOK   IthMutexLocker locker(::hHookMutex)

namespace { // unnamed

void GetDebugPriv()
{
  HANDLE  hToken;
  DWORD  dwRet;
  NTSTATUS status;

  TOKEN_PRIVILEGES Privileges = {1,{0x14,0,SE_PRIVILEGE_ENABLED}};

  NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

  status = NtAdjustPrivilegesToken(hToken, 0, &Privileges, sizeof(Privileges), 0, &dwRet);
  //if (STATUS_SUCCESS == status)
  //{
  //  admin = 1;
  //}
  //else
  //{
  //  WCHAR buffer[0x10];
  //  swprintf(buffer, L"%.8X",status);
  //  MessageBox(0, NotAdmin, buffer, 0);
  //}
  NtClose(hToken);
}

bool sendCommand(HANDLE hCmd, HostCommandType cmd)
{
  IO_STATUS_BLOCK ios;
  //SendParam sp = {};
  //sp.type = cmd;
  DWORD data = cmd;
  return hCmd && NT_SUCCESS(NtWriteFile(hCmd, 0,0,0, &ios, &data, sizeof(data), 0,0));
}

// jichi 9/22/2013: Change current directory to the same as main module path
// Otherwise NtFile* would not work for files with relative paths.
//BOOL ChangeCurrentDirectory()
//{
//  if (const wchar_t *path = GetMainModulePath()) // path to VNR's python exe
//    if (const wchar_t *base = wcsrchr(path, L'\\')) {
//      size_t len = base - path;
//      if (len < MAX_PATH) {
//        wchar_t buf[MAX_PATH];
//        wcsncpy(buf, path, len);
//        buf[len] = 0;
//        return SetCurrentDirectoryW(buf);
//      }
//    }
//  return FALSE;
//}

#if 0
bool injectUsingWin32Api(LPCWSTR path, HANDLE hProc)
{ return WinDbg::injectDllW(path, 0, hProc); }

bool ejectUsingWin32Api(HANDLE hModule, HANDLE hProc)
{ return WinDbg::ejectDll(hModule, hProc); }

// The original inject logic in ITH
bool injectUsingNTApi(LPCWSTR path, HANDLE hProc)
{
  LPVOID lpvAllocAddr = 0;
  DWORD dwWrite = 0x1000; //, len = 0;
  //if (IthIsWine())
  //  lpvAllocAddr = VirtualAllocEx(hProc, nullptr, dwWrite, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  //else
  NtAllocateVirtualMemory(hProc, &lpvAllocAddr, 0, &dwWrite, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  if (!lpvAllocAddr)
    return false;

  CheckThreadStart();

  //Copy module path into address space of target process.
  //if (IthIsWine())
  //  WriteProcessMemory(hProc, lpvAllocAddr, path, MAX_PATH << 1, &dwWrite);
  //else
  NtWriteVirtualMemory(hProc, lpvAllocAddr, (LPVOID)path, MAX_PATH << 1, &dwWrite);
  HANDLE hTH = IthCreateThread(LoadLibraryW, (DWORD)lpvAllocAddr, hProc);
  if (hTH == 0 || hTH == INVALID_HANDLE_VALUE) {
    DOUT("ERROR: failed to create remote cli thread");
    //ConsoleOutput(ErrorRemoteThread);
    return false;
  }
  // jichi 9/28/2013: no wait as it will not blocked
  NtWaitForSingleObject(hTH, 0, nullptr);
  THREAD_BASIC_INFORMATION info;
  NtQueryInformationThread(hTH, ThreadBasicInformation, &info, sizeof(info), &dwWrite);
  NtClose(hTH);

  // jichi 10/19/2014: Disable inject the second dll
  //if (info.ExitStatus) {
  //  //IthCoolDown();
  //  wcscpy(p, engine);
  //  //if (IthIsWine())
  //  //  WriteProcessMemory(hProc, lpvAllocAddr, path, MAX_PATH << 1, &dwWrite);
  //  //else
  //  NtWriteVirtualMemory(hProc, lpvAllocAddr, path, MAX_PATH << 1, &dwWrite);
  //  hTH = IthCreateThread(LoadLibraryW, (DWORD)lpvAllocAddr, hProc);
  //  if (hTH == 0 || hTH == INVALID_HANDLE_VALUE) {
  //    //ConsoleOutput(ErrorRemoteThread);
  //    ConsoleOutput("vnrhost:inject: ERROR: failed to create remote eng thread");
  //    return error;
  //  }
  //
  //  // jichi 9/28/2013: no wait as it will not blocked
  //  NtWaitForSingleObject(hTH, 0, nullptr);
  //  NtClose(hTH);
  //}

  dwWrite = 0;
  //if (IthIsWine())
  //  VirtualFreeEx(hProc, lpvAllocAddr, dwWrite, MEM_RELEASE);
  //else
  NtFreeVirtualMemory(hProc, &lpvAllocAddr, &dwWrite, MEM_RELEASE);
  return info.ExitStatus != -1;
}

bool ejectUsingNTApi(HANDLE hModule, HANDLE hProc)
{
  //IthCoolDown();
//#ifdef ITH_WINE // Nt series crash on wine
//  hThread = IthCreateThread(FreeLibrary, engine, hProc);
//#else
  HANDLE hThread = IthCreateThread(LdrUnloadDll, module, hProc);
//#endif // ITH_WINE
  if (hThread == 0 || hThread == INVALID_HANDLE_VALUE)
    return false;
  // jichi 10/22/2013: Timeout might crash vnrsrv
  //NtWaitForSingleObject(hThread, 0, (PLARGE_INTEGER)&timeout);
  NtWaitForSingleObject(hThread, 0, nullptr);
  //man->UnlockHookman();
  THREAD_BASIC_INFORMATION info;
  NtQueryInformationThread(hThread, ThreadBasicInformation, &info, sizeof(info), 0);
  NtClose(hThread);
  NtSetEvent(hPipeExist, 0);
  FreeThreadStart(hProc);
  return info.ExitStatus;
}
#endif // 0

bool Inject(HANDLE hProc)
{
  //LPWSTR dllname = (IthIsWindowsXp() && !IthIsWine()) ? DllNameXp : DllName;
  //LPCWSTR dllname = ITH_USE_XP_DLLS ? ITH_DLL_XP : ITH_DLL;
  //LPCWSTR dllname = ITH_DLL;
  //if (!IthCheckFile(dllname))
  //  return error;
  wchar_t path[MAX_PATH];
  size_t len = IthGetCurrentModulePath(path, MAX_PATH);
  if (!len)
    return false;

  wchar_t *p;
  for (p = path + len; *p != L'\\'; p--);
  p++; // ending with L"\\"

  //LPCWSTR mp = GetMainModulePath();
  //len = wcslen(mp);
  //memcpy(path, mp, len << 1);
  //memset(path + len, 0, (MAX_PATH - len) << 1);
  //LPWSTR p;
  //for (p = path + len; *p != L'\\'; p--); // Always a \ after drive letter.
  //p++;
  ::wcscpy(p, ITH_DLL);

  return WinDbg::injectDllW(path, 0, hProc);
  //if (IthIsWindowsXp()) // && !IthIsWine())
  //  return injectUsingWin32Api(path, hProc);
  //else
  //  return injectUsingNTApi(path, hProc);
}

} // unnamed namespace

void CreateNewPipe();

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  CC_UNUSED(lpvReserved);
  switch (fdwReason)
  {
  case DLL_PROCESS_ATTACH:
    LdrDisableThreadCalloutsForDll(hinstDLL);
    InitializeCriticalSection(&::cs);
    IthInitSystemService();
    GetDebugPriv();
    // jichi 12/20/2013: Since I already have a GUI, I don't have to InitCommonControls()
    //Used by timers.
    InitCommonControls();
    // jichi 8/24/2013: Create hidden window so that ITH can access timer and events
    hMainWnd = CreateWindowW(L"Button", L"InternalWindow", 0, 0, 0, 0, 0, 0, 0, hinstDLL, 0);
    //wm_register_hidden_class("vnrsrv.class");
    //hMainWnd = (HWND)wm_create_hidden_window("vnrsrv", "Button", hinstDLL);
    //ChangeCurrentDirectory();
    break;
  case DLL_PROCESS_DETACH:
    if (::running)
      Host_Close();
    DeleteCriticalSection(&::cs);
    IthCloseSystemService();
    //wm_destroy_window(hMainWnd);
	DestroyWindow(hMainWnd);
    break;
  default:
    break;
  }
  return true;
}

HANDLE IthOpenPipe(LPWSTR name, ACCESS_MASK direction)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us, name);
  SECURITY_DESCRIPTOR sd = {1};
  OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, &us, OBJ_CASE_INSENSITIVE, &sd, 0};
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  if (NT_SUCCESS(NtCreateFile(&hFile, direction, &oa, &isb, 0, 0, FILE_SHARE_READ, FILE_OPEN, 0, 0, 0)))
    return hFile;
  else
    return INVALID_HANDLE_VALUE;
}

enum { IHS_SIZE = 0x80 };
enum { IHS_BUFF_SIZE  = IHS_SIZE - sizeof(HookParam) };

struct InsertHookStruct
{
  SendParam sp;
  BYTE name_buffer[IHS_SIZE];
};

IHFSERVICE void IHFAPI Host_Init()
{
  InitializeCriticalSection(&::cs);
  GetDebugPriv();
}

IHFSERVICE void IHFAPI Host_Destroy()
{
  InitializeCriticalSection(&::cs);
}

IHFSERVICE BOOL IHFAPI Host_Open()
{
  BOOL result = false;
  EnterCriticalSection(&::cs);
  DWORD present;
  hServerMutex = IthCreateMutex(ITH_SERVER_MUTEX, 1, &present);
  if (present)
    //MessageBox(0,L"Already running.",0,0);
    // jichi 8/24/2013
    GROWL_WARN(L"I am sorry that this game is attached by some other VNR ><\nPlease restart the game and try again!");
  else if (!::running) {
    ::running = true;
    ::settings = new Settings;
    ::man = new HookManager;
    //cmdq = new CommandQueue;
    InitializeCriticalSection(&detach_cs);

    ::hHookMutex = IthCreateMutex(ITH_SERVER_HOOK_MUTEX, FALSE);
    result = true;
  }
  LeaveCriticalSection(&::cs);
  return result;
}

IHFSERVICE DWORD IHFAPI Host_Start()
{
  //IthBreak();
  CreateNewPipe();
  ::hPipeExist = IthCreateEvent(ITH_PIPEEXISTS_EVENT);
  NtSetEvent(::hPipeExist, nullptr);
  return 0;
}

IHFSERVICE DWORD IHFAPI Host_Close()
{
  BOOL result = FALSE;
  EnterCriticalSection(&::cs);
  if (::running) {
    ::running = FALSE;
    HANDLE hRecvPipe = IthOpenPipe(recv_pipe, GENERIC_WRITE);
    NtClose(hRecvPipe);
    NtClearEvent(::hPipeExist);
    //delete cmdq;
    delete man;
    delete settings;
    NtClose(::hHookMutex);
    NtClose(hServerMutex);
    NtClose(::hPipeExist);
    DeleteCriticalSection(&detach_cs);
    result = TRUE;
  }
  LeaveCriticalSection(&::cs);
  return result;
}

IHFSERVICE DWORD IHFAPI Host_GetPIDByName(LPCWSTR pwcTarget)
{
  DWORD dwSize = 0x20000,
        dwExpectSize = 0;
  LPVOID pBuffer = 0;
  SYSTEM_PROCESS_INFORMATION *spiProcessInfo;
  DWORD dwPid = 0;
  DWORD dwStatus;

  NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &dwSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  dwStatus = NtQuerySystemInformation(SystemProcessInformation, pBuffer, dwSize, &dwExpectSize);
  if (!NT_SUCCESS(dwStatus)) {
    NtFreeVirtualMemory(NtCurrentProcess(),&pBuffer,&dwSize,MEM_RELEASE);
    if (dwStatus != STATUS_INFO_LENGTH_MISMATCH || dwExpectSize < dwSize)
      return 0;
    dwSize = (dwExpectSize | 0xFFF) + 0x4001; //
    pBuffer = 0;
    NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &dwSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    dwStatus = NtQuerySystemInformation(SystemProcessInformation, pBuffer, dwSize, &dwExpectSize);
    if (!NT_SUCCESS(dwStatus)) goto _end;
  }

  for (spiProcessInfo = (SYSTEM_PROCESS_INFORMATION *)pBuffer; spiProcessInfo->dNext;) {
    spiProcessInfo = (SYSTEM_PROCESS_INFORMATION *)
      ((DWORD)spiProcessInfo + spiProcessInfo -> dNext);
    if (_wcsicmp(pwcTarget, spiProcessInfo -> usName.Buffer) == 0) {
      dwPid = spiProcessInfo->dUniqueProcessId;
      break;
    }
  }
  if (!dwPid)
    DOUT("pid not found");
  //if (dwPid == 0) ConsoleOutput(ErrorNoProcess);
_end:
  NtFreeVirtualMemory(NtCurrentProcess(),&pBuffer,&dwSize,MEM_RELEASE);
  return dwPid;
}

IHFSERVICE bool IHFAPI Host_InjectByPID(DWORD pid)
{
  WCHAR str[0x80];
  if (!::running)
    return 0;
  if (pid == current_process_id) {
    //ConsoleOutput(SelfAttach);
    DOUT("refuse to inject myself");
    return false;
  }
  if (man->GetProcessRecord(pid)) {
    //ConsoleOutput(AlreadyAttach);
    DOUT("already attached");
    return false;
  }
  swprintf(str, ITH_HOOKMAN_MUTEX_ L"%d", pid);
  DWORD s;
  NtClose(IthCreateMutex(str, 0, &s));
  if (s) {
    DOUT("already locked");
    return false;
  }
  CLIENT_ID id;
  OBJECT_ATTRIBUTES oa = {};
  HANDLE hProc;
  id.UniqueProcess = pid;
  id.UniqueThread = 0;
  oa.uLength = sizeof(oa);
  if (!NT_SUCCESS(NtOpenProcess(&hProc,
      PROCESS_QUERY_INFORMATION|
      PROCESS_CREATE_THREAD|
      PROCESS_VM_OPERATION|
      PROCESS_VM_READ|
      PROCESS_VM_WRITE,
      &oa, &id))) {
    //ConsoleOutput(ErrorOpenProcess);
    DOUT("failed to open process");
    return false;
  }

  //if (!engine)
  //  engine = ITH_USE_XP_DLLS ? ITH_ENGINE_XP_DLL : ITH_ENGINE_DLL;
  bool ok = Inject(hProc);
  //NtClose(hProc); //already closed
  if (!ok) {
    DOUT("inject failed");
    return false;
  }
  //swprintf(str, FormatInject, pid, module);
  //ConsoleOutput(str);
  DOUT("inject succeed");
  return true;
}

// jichi 7/16/2014: Test if process is valid before creating remote threads
// See: http://msdn.microsoft.com/en-us/library/ms687032.aspx
static bool isProcessTerminated(HANDLE hProc)
{ return WAIT_OBJECT_0 == ::WaitForSingleObject(hProc, 0); }
//static bool isProcessRunning(HANDLE hProc)
//{ return WAIT_TIMEOUT == ::WaitForSingleObject(hProc, 0); }

// jichi 7/16/2014: Test if process is valid before creating remote threads
//static bool isProcessRunning(DWORD pid)
//{
//  bool ret = false;
//  HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
//  if (hProc) {
//   DWORD status;
//   if (::GetExitCodeProcess(hProc, &status)) {
//     ret = status == STILL_ACTIVE;
//     ::CloseHandle(hProc);
//   } else
//     ret = true;
//  }
//  return ret;
//}

IHFSERVICE bool IHFAPI Host_ActiveDetachProcess(DWORD pid)
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

IHFSERVICE bool IHFAPI Host_HijackProcess(DWORD pid)
{
  //ITH_SYNC_HOOK;
  HANDLE hCmd = man->GetCmdHandleByPID(pid);
  return hCmd && sendCommand(hCmd, HOST_COMMAND_HIJACK_PROCESS);
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

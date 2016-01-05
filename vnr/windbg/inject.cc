// inject.cc
// 1/27/2013 jichi
#include "windbg/inject.h"
#include "windbg/windbg_p.h"
#include <cwchar> // for wcslen

//#define DEBUG "windbg::inject"
#include "sakurakit/skdebug.h"

WINDBG_BEGIN_NAMESPACE

// - Remote Injection -

BOOL InjectFunction1(LPCVOID addr, LPCVOID data, SIZE_T dataSize, DWORD pid, HANDLE hProcess, INT timeout)
{
  DOUT("enter: pid =" <<  pid);
  if (hProcess == INVALID_HANDLE_VALUE && pid) {
     hProcess = ::OpenProcess(PROCESS_INJECT_ACCESS, FALSE, pid);
     // TODO: Privilege elevation is not implemented. See: skwinsec.py.
     //if (!hProcess) {
     //   priv = SkProcessElevator('SeDebugPrivilege')
     //   if not priv.isEmpty():
     //     handle = win32api.OpenProcess(PROCESS_INJECT_ACCESS, 0, pid)
     //}
  }
  if (hProcess == INVALID_HANDLE_VALUE) {
    DOUT("exit: error: failed to get process handle");
    return FALSE;
  }

  BOOL ret = FALSE;
  if (LPVOID remoteData = ::VirtualAllocEx(hProcess, nullptr, dataSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)) {
    if (::WriteProcessMemory(hProcess, remoteData, data, dataSize, nullptr))
      if (HANDLE hThread = ::CreateRemoteThread(
          hProcess,
          nullptr, 0,
          reinterpret_cast<LPTHREAD_START_ROUTINE>(addr),
          remoteData,
          0, nullptr)) {
        ::WaitForSingleObject(hThread, timeout);
        ::CloseHandle(hThread);
        ret = TRUE;
      }
    ::VirtualFreeEx(hProcess, remoteData, dataSize, MEM_RELEASE);
  }
  ::CloseHandle(hProcess);
  DOUT("exit: ret =" << ret);
  return ret;
}

BOOL injectDllW(LPCWSTR dllPath, DWORD pid, HANDLE hProcess, INT timeout)
{
  DOUT("enter: pid =" <<  pid);
  LPCVOID fun = details::getModuleFunctionAddressA("LoadLibraryW", "kernel32.dll");
  if (!fun) {
    DOUT("exit error: cannot find function");
    return FALSE;
  }
  LPCVOID data = dllPath;
  SIZE_T dataSize = ::wcslen(dllPath) * 2 + 2; // L'\0'
  BOOL ok = InjectFunction1(fun, data, dataSize, pid, hProcess, timeout);
  DOUT("exit: ret =" << ok);
  return ok;
}

BOOL ejectDll(HANDLE hDll, DWORD pid, HANDLE hProcess, INT timeout)
{
  DOUT("enter: pid =" <<  pid);
  LPCVOID fun = details::getModuleFunctionAddressA("FreeLibrary", "kernel32.dll");
  if (!fun) {
    DOUT("exit error: cannot find function");
    return FALSE;
  }
  LPCVOID data = &hDll;
  SIZE_T dataSize = sizeof(hDll);
  BOOL ok = InjectFunction1(fun, data, dataSize, pid, hProcess, timeout);
  DOUT("exit: ret =" << ok);
  return ok;
}

WINDBG_END_NAMESPACE

// EOF

/*
enum { CREATE_THREAD_ACCESS = (PROCESS_CREATE_THREAD |
                              PROCESS_QUERY_INFORMATION |
                              PROCESS_VM_OPERATION |
                              PROCESS_VM_WRITE |
                              PROCESS_VM_READ  ) };


int InjectDll(HANDLE hProcess, HINSTANCE hInst) {
  HANDLE hThread;

  wchar_t dllFile[2*MAX_PATH];
  if (GetModuleFileNameW(hInst, dllFile, sizeof(dllFile)/2) > sizeof(dllFile)/2) return 0;

  void *loadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
  if (!loadLibraryW) return 0;

  wchar_t *name;
  if (!(name = wcsrchr(dllFile, '\\'))) return 0;
  name ++;
  wcscpy(name, DLL_NAME);
  if (GetFileAttributes(dllFile) == INVALID_FILE_ATTRIBUTES) return 0;

  size_t len = sizeof(wchar_t)*(1+wcslen(dllFile));
  void *remoteString = (LPVOID)VirtualAllocEx(hProcess,
                     NULL,
                     len,
                     MEM_RESERVE|MEM_COMMIT,
                     PAGE_READWRITE
                    );
  if (remoteString) {
    if (WriteProcessMemory(hProcess, (LPVOID)remoteString, dllFile, len, NULL)) {
      if (hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)loadLibraryW, (LPVOID)remoteString, 0,0)) {
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteString, len, MEM_FREE);
        // Make sure it's injected before resuming.
        return 1;
      }
    }
    VirtualFreeEx(hProcess, remoteString, len, MEM_FREE);
  }
  return 0;
}

int getPriv(const char * name) {
  HANDLE hToken;
  LUID seValue;
  TOKEN_PRIVILEGES tkp;

  if (!LookupPrivilegeValueA(NULL, name, &seValue) ||
    !OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
      return 0;
  }

  tkp.PrivilegeCount = 1;
  tkp.Privileges[0].Luid = seValue;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  int res = AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL);

  CloseHandle(hToken);
  return res;
}

inline int getDebugPriv() {
  return getPriv("SeDebugPrivilege");
}

int InjectIntoProcess(int pid) {
  HANDLE hProcess = OpenProcess(CREATE_THREAD_ACCESS, 0, pid);
  if (hProcess == 0) {
    getDebugPriv();
    hProcess = OpenProcess(CREATE_THREAD_ACCESS, 0, pid);
    if (!hProcess) return 0;
  }

  int out = InjectDll(hProcess);

  CloseHandle(hProcess);
  return out;
}
*/

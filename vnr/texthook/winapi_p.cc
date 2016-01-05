// apiwin_p.cc
// 10/6/2012 jichi
#include "texthook/winapi_p.h"
#include <windows.h>

WINAPI_BEGIN_NAMESPACE

bool IsProcessActiveWithId(DWORD dwProcessId)
{
  bool ret = false;
  if (HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId)) {
    DWORD dwExitCode;
    ret = ::GetExitCodeProcess(hProc, &dwExitCode) && (dwExitCode == STILL_ACTIVE);
    ::CloseHandle(hProc);
  }
  return ret;
}

WINAPI_END_NAMESPACE

// EOF

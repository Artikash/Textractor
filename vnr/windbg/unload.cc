// unload.cc
// 5/2/2014 jichi
#include "windbg/unload.h"

WINDBG_BEGIN_NAMESPACE

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
// See: http://stackoverflow.com/questions/3410130/dll-unloading-itself
BOOL unloadCurrentModule()
{
  auto fun = ::FreeLibrary;
  //auto fun = ::LdrUnloadDll;
  if (HANDLE h = ::CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fun, &__ImageBase, 0, NULL)) {
    ::CloseHandle(h);
    return TRUE;
  }
  return FALSE;
}

WINDBG_END_NAMESPACE

// EOF

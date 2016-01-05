#pragma once

// inject.h
// 1/27/2013 jichi

#include "windbg/windbg.h"

#include <windows.h>

WINDBG_BEGIN_NAMESPACE

enum { PROCESS_INJECT_ACCESS = PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ };
enum { INJECT_TIMEOUT = 3000 }; // wait at most 3 seconds for creating remote threads

/**
 *  Inject function with 1 argument
 *  Either pid or the process handle should be specified
 *  @param  addr  LONG  function memory address
 *  @param  arg  LPVOID  arg1 data
 *  @param  argSize  int  arg1 data size
 *  @param  pid  process id
 *  @param  hProcess  process handle
 *  @param  timeout  msec
 *  @return  BOOL
 */
BOOL injectFunction1(_In_ LPCVOID addr, _In_ LPCVOID arg, _In_ SIZE_T argSize,
    _In_ DWORD pid = 0, _In_ HANDLE hProcess = INVALID_HANDLE_VALUE,
    _In_ INT timeout = INJECT_TIMEOUT);

/**
 *  Either pid or the process handle should be specified
 *  @param  dllpath  ABSOLUTE path to dll
 *  @param  pid  process id
 *  @param  hProcess  process handle
 *  @param  timeout  msec
 *  @return  BOOL
 */
BOOL injectDllW(_In_ LPCWSTR dllPath,
  _In_ DWORD pid = 0, _In_ HANDLE hProcess = INVALID_HANDLE_VALUE,
  _In_ INT timeout = INJECT_TIMEOUT);

/**
 *  Either pid or the process handle should be specified
 *  @param  hDll  dll module handle
 *  @param  pid  process id
 *  @param  hProcess  process handle
 *  @param  timeout  msec
 *  @return  BOOL
 */
BOOL ejectDll(_In_ HANDLE hDll,
  _In_ DWORD pid = 0, _In_ HANDLE hProcess = INVALID_HANDLE_VALUE,
  _In_ INT timeout = INJECT_TIMEOUT);

WINDBG_END_NAMESPACE

// EOF

#pragma once

// hijack.h
// 1/27/2013 jichi

#include "windbg/windbg.h"
#include <windows.h>

WINDBG_BEGIN_NAMESPACE

/**
 * Replace the named function entry with the new one.
 * @param  stealFrom  instance of target module
 * @param  oldFunctionModule TODO
 * @param  functionName  name of the target function
 * @return  the orignal address if succeed, else nullptr
 *
 * See: http://www.codeproject.com/KB/DLL/DLL_Injection_tutorial.aspx
 */
PVOID overrideFunctionA(_In_ HMODULE stealFrom, _In_ LPCSTR oldFunctionModule,
                        _In_ LPCSTR functionName, _In_ LPCVOID newFunction);

WINDBG_END_NAMESPACE

// EOF

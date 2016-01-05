#pragma once

// windbg_p.h
// 1/27/2013 jichi

#include "windbg/windbg.h"
#include <windows.h>

WINDBG_BEGIN_NAMESPACE

namespace details { // unnamed

///  Return the address of func in module.
inline FARPROC getModuleFunctionAddressA(LPCSTR func, LPCSTR module = nullptr)
{ return ::GetProcAddress(::GetModuleHandleA(module), func); }

inline FARPROC getModuleFunctionAddressW(LPCSTR func, LPCWSTR module = nullptr)
{ return ::GetProcAddress(::GetModuleHandleW(module), func); }

} // unamed namespace details

WINDBG_END_NAMESPACE

// EOF

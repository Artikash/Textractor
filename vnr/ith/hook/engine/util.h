#pragma once

// util/util.h
// 8/23/2013 jichi

#include "config.h"

namespace Util {

DWORD GetCodeRange(DWORD hModule,DWORD *low, DWORD *high);
DWORD FindCallAndEntryBoth(DWORD fun, DWORD size, DWORD pt, DWORD sig);
DWORD FindCallOrJmpRel(DWORD fun, DWORD size, DWORD pt, bool jmp);
DWORD FindCallOrJmpAbs(DWORD fun, DWORD size, DWORD pt, bool jmp);
DWORD FindCallBoth(DWORD fun, DWORD size, DWORD pt);
DWORD FindCallAndEntryAbs(DWORD fun, DWORD size, DWORD pt, DWORD sig);
DWORD FindCallAndEntryRel(DWORD fun, DWORD size, DWORD pt, DWORD sig);
DWORD FindEntryAligned(DWORD start, DWORD back_range);
DWORD FindImportEntry(DWORD hModule, DWORD fun);

// jichi 4/15/2014: Copied from ITH CLI, for debugging purpose
DWORD FindModuleBase(DWORD hash);

bool SearchResourceString(LPCWSTR str);

/**
 *  @param  name  process name without path deliminator
 */
inline void GetProcessName(wchar_t *name)
{
  //assert(name);
  PLDR_DATA_TABLE_ENTRY it;
  __asm
  {
    mov eax,fs:[0x30]
    mov eax,[eax+0xc]
    mov eax,[eax+0xc]
    mov it,eax
  }
  ::wcscpy(name, it->BaseDllName.Buffer);
}

/**
 *  @param  path with process name and directy name
 */
inline void GetProcessPath(wchar_t *path)
{
  //assert(path);
  PLDR_DATA_TABLE_ENTRY it;
  __asm
  {
    mov eax,fs:[0x30]
    mov eax,[eax+0xc]
    mov eax,[eax+0xc]
    mov it,eax
  }
  ::wcscpy(path, it->FullDllName.Buffer);
}

/**
 *  @return  HANDLE  module handle
 */
inline DWORD GetModuleBase()
{
  __asm
  {
    mov eax,fs:[0x18]
    mov eax,[eax+0x30]
    mov eax,[eax+0xc]
    mov eax,[eax+0xc]
    mov eax,[eax+0x18]
  }
}

} // namespace Util

// EOF

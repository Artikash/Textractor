#pragma once

// util.h
// 8/23/2013 jichi

#include "common.h"

namespace Util {

bool unloadCurrentModule();

DWORD GetCodeRange(DWORD hModule,DWORD *low, DWORD *high);
DWORD FindCallAndEntryBoth(DWORD fun, DWORD size, DWORD pt, DWORD sig);
DWORD FindCallOrJmpRel(DWORD fun, DWORD size, DWORD pt, bool jmp);
DWORD FindCallOrJmpAbs(DWORD fun, DWORD size, DWORD pt, bool jmp);
DWORD FindCallBoth(DWORD fun, DWORD size, DWORD pt);
DWORD FindCallAndEntryAbs(DWORD fun, DWORD size, DWORD pt, DWORD sig);
DWORD FindCallAndEntryRel(DWORD fun, DWORD size, DWORD pt, DWORD sig);
DWORD FindEntryAligned(DWORD start, DWORD back_range);
DWORD FindImportEntry(DWORD hModule, DWORD fun);
bool CheckFile(LPCWSTR name);

bool SearchResourceString(LPCWSTR str);

std::vector<uint64_t> SearchMemory(const void* bytes, short length, DWORD protect = PAGE_EXECUTE);

} // namespace Util

// EOF

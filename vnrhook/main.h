#pragma once

// main.h
// 8/23/2013 jichi
// Branch: ITH/IHF_DLL.h, rev 66

#include "common.h"
#include "types.h"
#include "pipe.h"

void NewHook(const HookParam &hp, LPCSTR name, DWORD flag = HOOK_ENGINE);
void RemoveHook(uint64_t addr);
void SwitchTrigger(DWORD on);

// EOF

#pragma once

// main.h
// 8/23/2013 jichi
// Branch: ITH/IHF_DLL.h, rev 66

#include "common.h"
#include "pipe.h"

void ConsoleOutput(LPCSTR text); // jichi 12/25/2013: Used to return length of sent text
void NotifyHookInsert(HookParam hp, LPCSTR name);
void NotifyHookRemove(unsigned __int64 addr);
DWORD NewHook(const HookParam &hp, LPCSTR name, DWORD flag = HOOK_ENGINE);
DWORD RemoveHook(unsigned __int64 addr);
DWORD SwitchTrigger(DWORD on);

// 10/14/2014 jichi: disable GDI hooks
void EnableGDIHooks();
void EnableGDIPlusHooks();
void DisableGDIHooks();
void DisableGDIPlusHooks();
bool GDIHooksEnabled();
bool GDIPlusHooksEnabled();

// EOF

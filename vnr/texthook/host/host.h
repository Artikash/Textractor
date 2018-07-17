#pragma once

// host.h
// 8/23/2013 jichi
// Branch: ITH/IHF.h, rev 105

//#include "host/settings.h"
#include "config.h"
#include "host/hookman.h"
#include <string>

struct HookParam;

DLLEXPORT void OpenHost();
DLLEXPORT bool StartHost();
DLLEXPORT void CloseHost();
DLLEXPORT void GetHostHookManager(HookManager **hookman);
DLLEXPORT bool InjectProcessById(DWORD pid, DWORD timeout = 5000);
DLLEXPORT bool DetachProcessById(DWORD pid);
DLLEXPORT DWORD InsertHook(DWORD pid, const HookParam *hp, std::string name = "");
DLLEXPORT DWORD RemoveHook(DWORD pid, DWORD addr);

// EOF

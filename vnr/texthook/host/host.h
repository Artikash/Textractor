#pragma once

// host.h
// 8/23/2013 jichi
// Branch: ITH/IHF.h, rev 105

//#include "host/settings.h"
#include "config.h"
#include "host/hookman.h"
#include <string>

struct Settings;
struct HookParam;

IHFSERVICE void IHFAPI Host_Init();
IHFSERVICE void IHFAPI Host_Destroy();

IHFSERVICE void IHFAPI StartHost();
IHFSERVICE bool IHFAPI OpenHost();
IHFSERVICE void IHFAPI CloseHost();
IHFSERVICE void IHFAPI GetHostHookManager(HookManager **hookman);
IHFSERVICE void IHFAPI GetHostSettings(Settings **settings);
IHFSERVICE DWORD IHFAPI Host_GetPIDByName(LPCWSTR pwcTarget);
IHFSERVICE bool IHFAPI InjectProcessById(DWORD pid, DWORD timeout = 5000);
IHFSERVICE bool IHFAPI DetachProcessById(DWORD pid);
IHFSERVICE bool IHFAPI Host_HijackProcess(DWORD pid);
IHFSERVICE DWORD IHFAPI InsertHook(DWORD pid, HookParam *hp, std::string name = "");
IHFSERVICE DWORD IHFAPI Host_ModifyHook(DWORD pid, HookParam *hp);
IHFSERVICE DWORD IHFAPI Host_RemoveHook(DWORD pid, DWORD addr);
IHFSERVICE DWORD IHFAPI Host_AddLink(DWORD from, DWORD to);
IHFSERVICE DWORD IHFAPI Host_UnLink(DWORD from);
IHFSERVICE DWORD IHFAPI Host_UnLinkAll(DWORD from);

// EOF

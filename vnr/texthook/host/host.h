#pragma once

// host.h
// 8/23/2013 jichi
// Branch: ITH/IHF.h, rev 105

//#include "host/settings.h"
#include "config.h"
#include "host/hookman.h"

struct Settings;
struct HookParam;

IHFSERVICE void IHFAPI Host_Init();
IHFSERVICE void IHFAPI Host_Destroy();

IHFSERVICE DWORD IHFAPI Host_Start();
IHFSERVICE BOOL IHFAPI Host_Open();
IHFSERVICE DWORD IHFAPI Host_Close();
IHFSERVICE DWORD IHFAPI Host_GetHookManager(HookManager **hookman);
IHFSERVICE bool IHFAPI Host_GetSettings(Settings **settings);
IHFSERVICE DWORD IHFAPI Host_GetPIDByName(LPCWSTR pwcTarget);
IHFSERVICE bool IHFAPI Host_InjectByPID(DWORD pid);
IHFSERVICE bool IHFAPI Host_ActiveDetachProcess(DWORD pid);
IHFSERVICE bool IHFAPI Host_HijackProcess(DWORD pid);
IHFSERVICE DWORD IHFAPI Host_InsertHook(DWORD pid, HookParam *hp, LPCSTR name = nullptr);
IHFSERVICE DWORD IHFAPI Host_ModifyHook(DWORD pid, HookParam *hp);
IHFSERVICE DWORD IHFAPI Host_RemoveHook(DWORD pid, DWORD addr);
IHFSERVICE DWORD IHFAPI Host_AddLink(DWORD from, DWORD to);
IHFSERVICE DWORD IHFAPI Host_UnLink(DWORD from);
IHFSERVICE DWORD IHFAPI Host_UnLinkAll(DWORD from);

// EOF

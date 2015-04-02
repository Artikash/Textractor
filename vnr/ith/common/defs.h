#pragma once

// ith/common/defs.h
// 8/23/2013 jichi

// DLL files

//#define ITH_SERVER_DLL      L"vnrsrv.dll"
//#define ITH_CLIENT_DLL      L"vnrcli.dll"
//#define ITH_CLIENT_XP_DLL   L"vnrclixp.dll"
////#define ITH_CLIENT_UX_DLL   L"vnrcliux.dll"
//#define ITH_ENGINE_DLL      L"vnreng.dll"
//#define ITH_ENGINE_XP_DLL   L"vnrengxp.dll"
//#define ITH_ENGINE_UX_DLL   L"vnrengux.dll"

#define ITH_DLL     L"vnrhook.dll"
#define ITH_DLL_XP  L"vnrhookxp.dll"

// Pipes

#define ITH_TEXT_PIPE       L"\\??\\pipe\\VNR_TEXT"
#define ITH_COMMAND_PIPE    L"\\??\\pipe\\VNR_COMMAND"

// Sections

#define ITH_SECTION_        L"VNR_SECTION_" // _%d

// Mutex

#define ITH_PROCESS_MUTEX_  L"VNR_PROCESS_" // ITH_%d
#define ITH_HOOKMAN_MUTEX_  L"VNR_HOOKMAN_" // ITH_HOOKMAN_%d
#define ITH_DETACH_MUTEX_   L"VNR_DETACH_"  // ITH_DETACH_%d

#define ITH_GRANTPIPE_MUTEX L"VNR_GRANT_PIPE" // ITH_GRANT_PIPE

//#define ITH_ENGINE_MUTEX  L"VNR_ENGINE"   // ITH_ENGINE
#define ITH_CLIENT_MUTEX    L"VNR_CLIENT"   // ITH_DLL_RUNNING
#define ITH_SERVER_MUTEX    L"VNR_SERVER"   // ITH_RUNNING
#define ITH_SERVER_HOOK_MUTEX L"VNR_SERVER_HOOK"    // original

// Events

#define ITH_REMOVEHOOK_EVENT    L"VNR_REMOVE_HOOK"  // ITH_REMOVE_HOOK
#define ITH_MODIFYHOOK_EVENT    L"VNR_MODIFY_HOOK"  // ITH_MODIFY_HOOK
#define ITH_PIPEEXISTS_EVENT    L"VNR_PIPE_EXISTS"  // ITH_PIPE_EXIST

// EOF

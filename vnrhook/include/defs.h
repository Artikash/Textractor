#pragma once

// vnrhook/defs.h
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

// Pipes

#define ITH_TEXT_PIPE       L"\\\\.\\pipe\\VNR_TEXT"
#define ITH_COMMAND_PIPE    L"\\\\.\\pipe\\VNR_COMMAND"

// Sections

#define ITH_SECTION_        L"VNR_SECTION_" // _%d

// Mutex

#define ITH_HOOKMAN_MUTEX_      L"VNR_HOOKMAN_" // ITH_HOOKMAN_%d
#define ITH_GRANTPIPE_MUTEX     L"VNR_GRANT_PIPE" // ITH_GRANT_PIPE

// EOF

#pragma once

// ith/common/growl.h
// 9/17/2013 jichi

//#ifdef ITH_HAS_GROWL

#include <windows.h>
#include "ith/common/string.h"

#define ITH_MSG_A(_msg)     MessageBoxA(nullptr, _msg, "VNR Message", MB_OK)
#define ITH_MSG(_msg)       MessageBoxW(nullptr, _msg, L"VNR Message", MB_OK)
#define ITH_WARN(_msg)      MessageBoxW(nullptr, _msg, L"VNR Warning", MB_OK)
#define ITH_ERROR(_msg)     MessageBoxW(nullptr, _msg, L"VNR Error", MB_OK)

inline void ITH_GROWL_DWORD(DWORD value)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD: %x", value);
  ITH_MSG(buf);
}

inline void ITH_GROWL_DWORD2(DWORD v, DWORD v2)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD2: %x,%x", v, v2);
  ITH_MSG(buf);
}

inline void ITH_GROWL_DWORD3(DWORD v, DWORD v2, DWORD v3)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD3: %x,%x,%x", v, v2, v3);
  ITH_MSG(buf);
}

inline void ITH_GROWL_DWORD4(DWORD v, DWORD v2, DWORD v3, DWORD v4)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD4: %x,%x,%x,%x", v, v2, v3, v4);
  ITH_MSG(buf);
}

inline void ITH_GROWL_DWORD5(DWORD v, DWORD v2, DWORD v3, DWORD v4, DWORD v5)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD5: %x,%x,%x,%x,%x", v, v2, v3, v4, v5);
  ITH_MSG(buf);
}

inline void ITH_GROWL_DWORD6(DWORD v, DWORD v2, DWORD v3, DWORD v4, DWORD v5, DWORD v6)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD6: %x,%x,%x,%x,%x,%x", v, v2, v3, v4, v5, v6);
  ITH_MSG(buf);
}

inline void ITH_GROWL_DWORD7(DWORD v, DWORD v2, DWORD v3, DWORD v4, DWORD v5, DWORD v6, DWORD v7)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD7: %x,%x,%x,%x,%x,%x,%x", v, v2, v3, v4, v5, v6, v7);
  ITH_MSG(buf);
}

inline void ITH_GROWL_DWORD8(DWORD v, DWORD v2, DWORD v3, DWORD v4, DWORD v5, DWORD v6, DWORD v7, DWORD v8)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD8: %x,%x,%x,%x,%x,%x,%x,%x", v, v2, v3, v4, v5, v6, v7, v8);
  ITH_MSG(buf);
}

inline void ITH_GROWL_DWORD9(DWORD v, DWORD v2, DWORD v3, DWORD v4, DWORD v5, DWORD v6, DWORD v7, DWORD v8, DWORD v9)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD9: %x,%x,%x,%x,%x,%x,%x,%x,%x", v, v2, v3, v4, v5, v6, v7, v8, v9);
  ITH_MSG(buf);
}

inline void ITH_GROWL(DWORD v) { ITH_GROWL_DWORD(v); }
inline void ITH_GROWL(LPCWSTR v) { ITH_MSG(v); }
inline void ITH_GROWL(LPCSTR v) { ITH_MSG_A(v); }

//#endif // ITH_HAS_GROWL

// EOF

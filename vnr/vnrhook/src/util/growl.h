#pragma once

// growl.h
// 9/17/2013 jichi

//#ifdef GROWL_HAS_GROWL

#include <windows.h>
#include <cstdio>

#define GROWL_MSG_A(_msg)     MessageBoxA(nullptr, _msg, "VNR Message", MB_OK)
#define GROWL_MSG(_msg)       MessageBoxW(nullptr, _msg, L"VNR Message", MB_OK)
#define GROWL_WARN(_msg)      MessageBoxW(nullptr, _msg, L"VNR Warning", MB_OK)
#define GROWL_ERROR(_msg)     MessageBoxW(nullptr, _msg, L"VNR Error", MB_OK)

inline void GROWL_DWORD(DWORD value)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD: %x", value);
  GROWL_MSG(buf);
}

inline void GROWL_DWORD2(DWORD v, DWORD v2)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD2: %x,%x", v, v2);
  GROWL_MSG(buf);
}

inline void GROWL_DWORD3(DWORD v, DWORD v2, DWORD v3)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD3: %x,%x,%x", v, v2, v3);
  GROWL_MSG(buf);
}

inline void GROWL_DWORD4(DWORD v, DWORD v2, DWORD v3, DWORD v4)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD4: %x,%x,%x,%x", v, v2, v3, v4);
  GROWL_MSG(buf);
}

inline void GROWL_DWORD5(DWORD v, DWORD v2, DWORD v3, DWORD v4, DWORD v5)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD5: %x,%x,%x,%x,%x", v, v2, v3, v4, v5);
  GROWL_MSG(buf);
}

inline void GROWL_DWORD6(DWORD v, DWORD v2, DWORD v3, DWORD v4, DWORD v5, DWORD v6)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD6: %x,%x,%x,%x,%x,%x", v, v2, v3, v4, v5, v6);
  GROWL_MSG(buf);
}

inline void GROWL_DWORD7(DWORD v, DWORD v2, DWORD v3, DWORD v4, DWORD v5, DWORD v6, DWORD v7)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD7: %x,%x,%x,%x,%x,%x,%x", v, v2, v3, v4, v5, v6, v7);
  GROWL_MSG(buf);
}

inline void GROWL_DWORD8(DWORD v, DWORD v2, DWORD v3, DWORD v4, DWORD v5, DWORD v6, DWORD v7, DWORD v8)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD8: %x,%x,%x,%x,%x,%x,%x,%x", v, v2, v3, v4, v5, v6, v7, v8);
  GROWL_MSG(buf);
}

inline void GROWL_DWORD9(DWORD v, DWORD v2, DWORD v3, DWORD v4, DWORD v5, DWORD v6, DWORD v7, DWORD v8, DWORD v9)
{
  WCHAR buf[100];
  swprintf(buf, L"DWORD9: %x,%x,%x,%x,%x,%x,%x,%x,%x", v, v2, v3, v4, v5, v6, v7, v8, v9);
  GROWL_MSG(buf);
}

inline void GROWL(DWORD v) { GROWL_DWORD(v); }
inline void GROWL(LPCWSTR v) { GROWL_MSG(v); }
inline void GROWL(LPCSTR v) { GROWL_MSG_A(v); }

//#endif // GROWL_HAS_GROWL

// EOF

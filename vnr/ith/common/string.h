#pragma once

// ith/common/string.h
// 8/9/2013 jichi
// Branch: ITH/string.h, rev 66

#ifdef ITH_HAS_CRT   // ITH is linked with msvcrt dlls
# include <cstdio>
# include <cstring>

#else
# define _INC_SWPRINTF_INL_
# define CRT_IMPORT __declspec(dllimport)

#include <windows.h> // for wchar_t
extern "C" {
CRT_IMPORT int swprintf(wchar_t *src, const wchar_t *fmt, ...);
CRT_IMPORT int sprintf(char *src, const char *fmt, ...);
CRT_IMPORT int swscanf(const wchar_t *src,  const wchar_t *fmt, ...);
CRT_IMPORT int sscanf(const char *src, const char *fmt, ...);
CRT_IMPORT int wprintf(const wchar_t *fmt, ...);
CRT_IMPORT int printf(const char *fmt, ...);
CRT_IMPORT int _wputs(const wchar_t *src);
CRT_IMPORT int puts(const char *src);
CRT_IMPORT int _stricmp(const char *x, const char *y);
CRT_IMPORT int _wcsicmp(const wchar_t *x, const wchar_t *y);
//CRT_IMPORT size_t strlen(const char *);
//CRT_IMPORT size_t wcslen(const wchar_t *);
//CRT_IMPORT char *strcpy(char *,const char *);
//CRT_IMPORT wchar_t *wcscpy(wchar_t *,const wchar_t *);
CRT_IMPORT void *memmove(void *dst, const void *src, size_t sz);
CRT_IMPORT const char *strchr(const char *src, int val);
CRT_IMPORT int strncmp(const char *x, const char *y, size_t sz);
} // extern "C"

#endif // ITH_HAS_CRT

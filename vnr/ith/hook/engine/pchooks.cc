// pchooks.cc
// 8/1/2014 jichi

#include "engine/pchooks.h"
#include "hook.h"

#define DEBUG "vnrcli"
#define DPRINT(cstr) ConsoleOutput(DEBUG ":" __FUNCTION__ ":" cstr) // defined in vnrcli

// 8/1/2014 jichi: Split is not used.
// Although split is specified, USING_SPLIT is not assigned.

// Use LPASTE to convert to wchar_t
// http://bytes.com/topic/c/answers/135834-defining-wide-character-strings-macros
#define LPASTE(s) L##s
#define L(s) LPASTE(s)
#define NEW_HOOK(_fun, _data, _data_ind, _split_off, _split_ind, _type, _len_off) \
  { \
    HookParam hp = {}; \
    hp.addr = (DWORD)_fun; \
    hp.off = _data; \
    hp.ind = _data_ind; \
    hp.split = _split_off; \
    hp.split_ind = _split_ind; \
    hp.type = _type; \
    hp.length_offset = _len_off; \
    NewHook(hp, L(#_fun)); \
  }

// jichi 7/17/2014: Renamed from InitDefaultHook
void PcHooks::hookGDIFunctions()
{
  DPRINT("enter");
  // int TextHook::InitHook(LPVOID addr, DWORD data, DWORD data_ind, DWORD split_off, DWORD split_ind, WORD type, DWORD len_off)
  //
  // jichi 9/8/2013: Guessed meaning
  // - data(off): 4 * the n-th (base 1) parameter representing the data of the string
  // - len_off:
  //   - the n-th (base 1) parameter representing the length of the string
  //   - or 1 if is char
  //   - or 0 if detect on run time
  // - type: USING_STRING if len_off != 1 else BIG_ENDIAN or USING_UNICODE
  //
  // Examples:
  // int WINAPI lstrlenA(LPCSTR lpString)
  // - data: 4 * 1 = 4, as lpString is the first
  // - len_off: 0, as no parameter representing string length
  // - type: BIG_ENDIAN, since len_off == 1
  // BOOL GetTextExtentPoint32(HDC hdc, LPCTSTR lpString, int c, LPSIZE lpSize);
  // - data: 4 * 2 = 0x8, as lpString is the second
  // - len_off: 3, as nCount is the 3rd parameter
  // - type: USING_STRING, since len_off != 1
  //
  // Note: All functions does not have NO_CONTEXT attribute and will be filtered.

  enum stack {
    s_retaddr = 0
    , s_arg1 = 4 * 1 // 0x4
    , s_arg2 = 4 * 2 // 0x8
    , s_arg3 = 4 * 3 // 0xc
    , s_arg4 = 4 * 4 // 0x10
    , s_arg5 = 4 * 5 // 0x14
    , s_arg6 = 4 * 6 // 0x18
  };

//#define _(Name, ...) \
//  hookman[HF_##Name].InitHook(Name, __VA_ARGS__); \
//  hookman[HF_##Name].SetHookName(names[HF_##Name]);

  // Always use s_arg1 = hDC as split_off
  // 7/26/2014 jichi: Why there is no USING_SPLIT type?

  // gdi32.dll
  NEW_HOOK(GetTextExtentPoint32A, s_arg2, 0,s_arg1,0, USING_STRING,  3) // BOOL GetTextExtentPoint32(HDC hdc, LPCTSTR lpString, int c, LPSIZE lpSize);
  NEW_HOOK(GetGlyphOutlineA,      s_arg2, 0,s_arg1,0, BIG_ENDIAN,    1) // DWORD GetGlyphOutline(HDC hdc,  UINT uChar,  UINT uFormat, LPGLYPHMETRICS lpgm, DWORD cbBuffer, LPVOID lpvBuffer, const MAT2 *lpmat2);
  NEW_HOOK(ExtTextOutA,           s_arg6, 0,s_arg1,0, USING_STRING,  7) // BOOL ExtTextOut(HDC hdc, int X, int Y, UINT fuOptions, const RECT *lprc, LPCTSTR lpString, UINT cbCount, const INT *lpDx);
  NEW_HOOK(TextOutA,              s_arg4, 0,s_arg1,0, USING_STRING,  5) // BOOL TextOut(HDC hdc, int nXStart, int nYStart, LPCTSTR lpString, int cchString);
  NEW_HOOK(GetCharABCWidthsA,     s_arg2, 0,s_arg1,0, BIG_ENDIAN,    1) // BOOL GetCharABCWidths(HDC hdc, UINT uFirstChar, UINT uLastChar,  LPABC lpabc);
  NEW_HOOK(GetTextExtentPoint32W, s_arg2, 0,s_arg1,0, USING_UNICODE|USING_STRING, 3)
  NEW_HOOK(GetGlyphOutlineW,      s_arg2, 0,s_arg1,0, USING_UNICODE, 1)
  NEW_HOOK(ExtTextOutW,           s_arg6, 0,s_arg1,0, USING_UNICODE|USING_STRING, 7)
  NEW_HOOK(TextOutW,              s_arg4, 0,s_arg1,0, USING_UNICODE|USING_STRING, 5)
  NEW_HOOK(GetCharABCWidthsW,     s_arg2, 0,s_arg1,0, USING_UNICODE, 1)

  // user32.dll
  NEW_HOOK(DrawTextA,             s_arg2, 0,s_arg1,0, USING_STRING,  3) // int DrawText(HDC hDC, LPCTSTR lpchText, int nCount, LPRECT lpRect, UINT uFormat);
  NEW_HOOK(DrawTextExA,           s_arg2, 0,s_arg1,0, USING_STRING,  3) // int DrawTextEx(HDC hdc, LPTSTR lpchText,int cchText, LPRECT lprc, UINT dwDTFormat, LPDRAWTEXTPARAMS lpDTParams);
  NEW_HOOK(DrawTextW,             s_arg2, 0,s_arg1,0, USING_UNICODE|USING_STRING, 3)
  NEW_HOOK(DrawTextExW,           s_arg2, 0,s_arg1,0, USING_UNICODE|USING_STRING, 3)
//#undef _
  DPRINT("leave");
}

// jichi 10/2/2013
// Note: All functions does not have NO_CONTEXT attribute and will be filtered.
void PcHooks::hookLstrFunctions()
{
  DPRINT("enter");
  // int TextHook::InitHook(LPVOID addr, DWORD data, DWORD data_ind, DWORD split_off, DWORD split_ind, WORD type, DWORD len_off)

  enum stack {
    s_retaddr = 0
    , s_arg1 = 4 * 1 // 0x4
    //, s_arg2 = 4 * 2 // 0x8
    //, s_arg3 = 4 * 3 // 0xc
    //, s_arg4 = 4 * 4 // 0x10
    //, s_arg5 = 4 * 5 // 0x14
    //, s_arg6 = 4 * 6 // 0x18
  };

  // http://msdn.microsoft.com/en-us/library/78zh94ax.aspx
  // int WINAPI lstrlen(LPCTSTR lpString);
  // Lstr functions usually extracts rubbish, and might crash certain games like 「Magical Marriage Lunatics!!」
  // Needed by Gift
  // Use arg1 address for both split and data
  NEW_HOOK(lstrlenA, s_arg1, 0,s_arg1,0, USING_STRING, 0) // 9/8/2013 jichi: int WINAPI lstrlen(LPCTSTR lpString);
  NEW_HOOK(lstrlenW, s_arg1, 0,s_arg1,0, USING_UNICODE|USING_STRING, 0) // 9/8/2013 jichi: add lstrlen

  // size_t strlen(const char *str);
  // size_t strlen_l(const char *str, _locale_t locale);
  // size_t wcslen(const wchar_t *str);
  // size_t wcslen_l(const wchar_t *str, _locale_t locale);
  // size_t _mbslen(const unsigned char *str);
  // size_t _mbslen_l(const unsigned char *str, _locale_t locale);
  // size_t _mbstrlen(const char *str);
  // size_t _mbstrlen_l(const char *str, _locale_t locale);

  // http://msdn.microsoft.com/en-us/library/ex0hs2ad.aspx
  // Needed by 娘姉妹
  //
  // <tchar.h>
  // char *_strinc(const char *current, _locale_t locale);
  // wchar_t *_wcsinc(const wchar_t *current, _locale_t locale);
  // <mbstring.h>
  // unsigned char *_mbsinc(const unsigned char *current);
  // unsigned char *_mbsinc_l(const unsigned char *current, _locale_t locale);
  //_(L"_strinc", _strinc, 4,  0,4,0, USING_STRING, 0) // 12/13/2013 jichi
  //_(L"_wcsinc", _wcsinc, 4,  0,4,0, USING_UNICODE|USING_STRING, 0)
  DPRINT("leave");
}

void PcHooks::hookWcharFunctions()
{
  DPRINT("enter");
  // 12/1/2013 jichi:
  // AlterEgo
  // http://tieba.baidu.com/p/2736475133
  // http://www.hongfire.com/forum/showthread.php/36807-AGTH-text-extraction-tool-for-games-translation/page355
  //
  // MultiByteToWideChar
  // http://blgames.proboards.com/thread/265
  //
  // WideCharToMultiByte
  // http://www.hongfire.com/forum/showthread.php/36807-AGTH-text-extraction-tool-for-games-translation/page156
  //
  // int MultiByteToWideChar(
  //   _In_       UINT CodePage,
  //   _In_       DWORD dwFlags,
  //   _In_       LPCSTR lpMultiByteStr, // hook here
  //   _In_       int cbMultiByte,
  //   _Out_opt_  LPWSTR lpWideCharStr,
  //   _In_       int cchWideChar
  // );
  // int WideCharToMultiByte(
  //   _In_       UINT CodePage,
  //   _In_       DWORD dwFlags,
  //   _In_       LPCWSTR lpWideCharStr,
  //   _In_       int cchWideChar,
  //   _Out_opt_  LPSTR lpMultiByteStr,
  //   _In_       int cbMultiByte,
  //   _In_opt_   LPCSTR lpDefaultChar,
  //   _Out_opt_  LPBOOL lpUsedDefaultChar
  // );

  enum stack {
    s_retaddr = 0
    //, s_arg1 = 4 * 1 // 0x4
    //, s_arg2 = 4 * 2 // 0x8
    , s_arg3 = 4 * 3 // 0xc
    //, s_arg4 = 4 * 4 // 0x10
    //, s_arg5 = 4 * 5 // 0x14
    //, s_arg6 = 4 * 6 // 0x18
  };

  // 3/17/2014 jichi: Temporarily disabled
  // http://sakuradite.com/topic/159
  NEW_HOOK(MultiByteToWideChar, s_arg3, 0,4,0, USING_STRING, 4)
  NEW_HOOK(WideCharToMultiByte, s_arg3, 0,4,0, USING_UNICODE|USING_STRING, 4)
  DPRINT("leave");
}

// EOF

#pragma once
//#include "ith/common/const.h"

// ppsspp/funcinfo.h
// 12/26/2014
// See: https://github.com/hrydgard/ppsspp

// Core/HLE (High Level Emulator)
// - sceCcc
//   #void sceCccSetTable(u32 jis2ucs, u32 ucs2jis)
//   int sceCccUTF8toUTF16(u32 dstAddr, u32 dstSize, u32 srcAddr)
//   int sceCccUTF8toSJIS(u32 dstAddr, u32 dstSize, u32 srcAddr)
//   int sceCccUTF16toUTF8(u32 dstAddr, u32 dstSize, u32 srcAddr)
//   int sceCccUTF16toSJIS(u32 dstAddr, u32 dstSize, u32 srcAddr)
//   int sceCccSJIStoUTF8(u32 dstAddr, u32 dstSize, u32 srcAddr)
//   int sceCccSJIStoUTF16(u32 dstAddr, u32 dstSize, u32 srcAddr)
//   int sceCccStrlenUTF8(u32 strAddr)
//   int sceCccStrlenUTF16(u32 strAddr)
//   int sceCccStrlenSJIS(u32 strAddr)
//   u32 sceCccEncodeUTF8(u32 dstAddrAddr, u32 ucs)
//   void sceCccEncodeUTF16(u32 dstAddrAddr, u32 ucs)
//   u32 sceCccEncodeSJIS(u32 dstAddrAddr, u32 jis)
//   u32 sceCccDecodeUTF8(u32 dstAddrAddr)
//   u32 sceCccDecodeUTF16(u32 dstAddrAddr)
//   u32 sceCccDecodeSJIS(u32 dstAddrAddr)
//   int sceCccIsValidUTF8(u32 c)
//   int sceCccIsValidUTF16(u32 c)
//   int sceCccIsValidSJIS(u32 c)
//   int sceCccIsValidUCS2(u32 c)
//   int sceCccIsValidUCS4(u32 c)
//   int sceCccIsValidJIS(u32 c)
//   int sceCccIsValidUnicode(u32 c)
//   #u32 sceCccSetErrorCharUTF8(u32 c)
//   #u32 sceCccSetErrorCharUTF16(u32 c)
//   #u32 sceCccSetErrorCharSJIS(u32 c)
//   u32 sceCccUCStoJIS(u32 c, u32 alt)
//   u32 sceCccJIStoUCS(u32 c, u32 alt)
// - sceFont: search charCode
//   int sceFontGetCharInfo(u32 fontHandle, u32 charCode, u32 charInfoPtr)
//   int sceFontGetShadowInfo(u32 fontHandle, u32 charCode, u32 charInfoPtr)
//   int sceFontGetCharImageRect(u32 fontHandle, u32 charCode, u32 charRectPtr)
//   int sceFontGetShadowImageRect(u32 fontHandle, u32 charCode, u32 charRectPtr)
//   int sceFontGetCharGlyphImage(u32 fontHandle, u32 charCode, u32 glyphImagePtr)
//   int sceFontGetCharGlyphImage_Clip(u32 fontHandle, u32 charCode, u32 glyphImagePtr, int clipXPos, int clipYPos, int clipWidth, int clipHeight)
//   #int sceFontSetAltCharacterCode(u32 fontLibHandle, u32 charCode)
//   int sceFontGetShadowGlyphImage(u32 fontHandle, u32 charCode, u32 glyphImagePtr)
//   int sceFontGetShadowGlyphImage_Clip(u32 fontHandle, u32 charCode, u32 glyphImagePtr, int clipXPos, int clipYPos, int clipWidth, int clipHeight)
// - sceKernelInterrupt
//   u32 sysclib_strcat(u32 dst, u32 src)
//   int sysclib_strcmp(u32 dst, u32 src)
//   u32 sysclib_strcpy(u32 dst, u32 src)
//   u32 sysclib_strlen(u32 src)
//
// Sample debug string:
//     006EFD8E   PUSH PPSSPPWi.00832188                    ASCII "sceCccEncodeSJIS(%08x, U+%04x)"
// Corresponding source code in sceCcc:
//     ERROR_LOG(HLE, "sceCccEncodeSJIS(%08x, U+%04x): invalid pointer", dstAddrAddr, jis);

struct PPSSPPFunction
{
  const wchar_t *hookName; // hook name
  size_t argIndex;      // argument index
  unsigned long hookType;       // hook parameter type
  unsigned long hookSplit;      // hook parameter split, positive: stack, negative: registers
  const char *pattern;  // debug string used within the function
};

// jichi 7/14/2014: UTF-8 is treated as STRING
// http://867258173.diandian.com/post/2014-06-26/40062099618
// sceFontGetCharGlyphImage_Clip
// Sample game: [KID] Monochrome: sceFontGetCharInfo, sceFontGetCharGlyphImage_Clip
//
// Example: { L"sceFontGetCharInfo", 2, USING_UNICODE, 4, "sceFontGetCharInfo(" }
// Text is at arg2, using arg1 as split
#define PPSSPP_FUNCTIONS_INITIALIZER \
    { L"sceCccStrlenSJIS",  1, USING_STRING,  0, "sceCccStrlenSJIS(" } \
  , { L"sceCccStrlenUTF8",  1, USING_UTF8,    0, "sceCccStrlenUTF8(" } \
  , { L"sceCccStrlenUTF16", 1, USING_UNICODE, 0, "sceCccStrlenUTF16(" } \
\
  , { L"sceCccSJIStoUTF8",  3, USING_UTF8,    0, "sceCccSJIStoUTF8(" } \
  , { L"sceCccSJIStoUTF16", 3, USING_STRING,  0, "sceCccSJIStoUTF16(" } \
  , { L"sceCccUTF8toSJIS",  3, USING_UTF8,    0, "sceCccUTF8toSJIS(" } \
  , { L"sceCccUTF8toUTF16", 3, USING_UTF8,    0, "sceCccUTF8toUTF16(" } \
  , { L"sceCccUTF16toSJIS", 3, USING_UNICODE, 0, "sceCccUTF16toSJIS(" } \
  , { L"sceCccUTF16toUTF8", 3, USING_UNICODE, 0, "sceCccUTF16toUTF8(" } \
\
  , { L"sceFontGetCharInfo",              2, USING_UNICODE, 4, "sceFontGetCharInfo(" } \
  , { L"sceFontGetShadowInfo",            2, USING_UNICODE, 4, "sceFontGetShadowInfo("} \
  , { L"sceFontGetCharImageRect",         2, USING_UNICODE, 4, "sceFontGetCharImageRect(" } \
  , { L"sceFontGetShadowImageRect",       2, USING_UNICODE, 4, "sceFontGetShadowImageRect(" } \
  , { L"sceFontGetCharGlyphImage",        2, USING_UNICODE, 4, "sceFontGetCharGlyphImage(" } \
  , { L"sceFontGetCharGlyphImage_Clip",   2, USING_UNICODE, 4, "sceFontGetCharGlyphImage_Clip(" } \
  , { L"sceFontGetShadowGlyphImage",      2, USING_UNICODE, 4, "sceFontGetShadowGlyphImage(" } \
  , { L"sceFontGetShadowGlyphImage_Clip", 2, USING_UNICODE, 4, "sceFontGetShadowGlyphImage_Clip(" } \
\
  , { L"sysclib_strcat", 2, USING_STRING, 0, "Untested sysclib_strcat(" } \
  , { L"sysclib_strcpy", 2, USING_STRING, 0, "Untested sysclib_strcpy(" } \
  , { L"sysclib_strlen", 1, USING_STRING, 0, "Untested sysclib_strlen(" }

  // Disabled as I am not sure how to deal with the source string
  //, { L"sceCccEncodeSJIS", 2, USING_STRING, 0, "sceCccEncodeSJIS(" }
  //, { L"sceCccEncodeUTF8", 2, USING_UTF8,   0, "sceCccEncodeUTF8(" }
  //, { L"sceCccEncodeUTF16", 2, USING_UNICODE, 0, "sceCccEncodeUTF16(" }
  //, { L"sysclib_strcmp", 2, USING_STRING, 0, "Untested sysclib_strcmp(" }

// EOF

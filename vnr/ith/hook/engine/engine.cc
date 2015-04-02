// eng/engine.cc
// 8/9/2013 jichi
// Branch: ITH_Engine/engine.cpp, revision 133

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "engine/engine.h"
#include "engine/match.h"
#include "engine/hookdefs.h"
#include "engine/util.h"
#include "hook.h"
#include "ith/sys/sys.h"
#include "ith/common/except.h"
#include "ith/import/mono/types.h"
#include "ith/import/mono/funcinfo.h"
#include "ith/import/ppsspp/funcinfo.h"
#include "memdbg/memsearch.h"
#include "ntinspect/ntinspect.h"
#include "disasm/disasm.h"
#include "winversion/winversion.h"
#include "cpputil/cppcstring.h"
#include "ccutil/ccmacro.h"
//#include <cctype>

// jichi 7/6/2014: read esp_base
#define retof(esp_base)         *(DWORD *)(esp_base) // return address
#define regof(name, esp_base)   *(DWORD *)((esp_base) + pusha_##name##_off - 4)
#define argof(count, esp_base)  *(DWORD *)((esp_base) + 4 * (count)) // starts from 1 instead of 0

//#define ConsoleOutput(...)  (void)0     // jichi 8/18/2013: I don't need ConsoleOutput

//#define DEBUG "engine.h"

enum { VNR_TEXT_CAPACITY = 1500 }; // estimated max number of bytes allowed in VNR, slightly larger than VNR's text limit (1000)

#ifdef DEBUG
# include "ith/common/growl.h"
//# include "uniquemap.h"
//# include "uniquemap.cc"
namespace { // unnamed debug functions
// jichi 12/17/2013: Copied from int TextHook::GetLength(DWORD base, DWORD in)
int GetHookDataLength(const HookParam &hp, DWORD base, DWORD in)
{
  if (CC_UNLIKELY(!base))
    return 0;
  int len;
  switch (hp.length_offset) {
  default: // jichi 12/26/2013: I should not put this default branch to the end
    len = *((int *)base + hp.length_offset);
    if (len >= 0) {
      if (hp.type & USING_UNICODE)
        len <<= 1;
      break;
    }
    else if (len != -1)
      break;
    //len == -1 then continue to case 0.
  case 0:
    if (hp.type & USING_UNICODE)
      len = wcslen((LPCWSTR)in) << 1;
    else
      len = strlen((LPCSTR)in);
    break;
  case 1:
    if (hp.type & USING_UNICODE)
      len = 2;
    else {
      if (hp.type & BIG_ENDIAN)
        in >>= 8;
      len = LeadByteTable[in&0xff];  //Slightly faster than IsDBCSLeadByte
    }
    break;
  }
  // jichi 12/25/2013: This function originally return -1 if failed
  //return len;
  return max(0, len);
}
} // unnamed
#endif // DEBUG

namespace { // unnamed helpers

int PPSSPP_VERSION[4] = { 0, 9, 8, 0 }; // 0.9.8 by default

enum : DWORD {
  PPSSPP_MEMORY_SEARCH_STEP_98 = 0x01000000
  , PPSSPP_MEMORY_SEARCH_STEP_99 = 0x00050000
  //, step = 0x1000 // step  must be at least 0x1000 (offset in SearchPattern)
  //, step = 0x00010000 // crash otoboku PSP on 0.9.9 since 5pb is wrongly inserted
};

enum : BYTE { XX = MemDbg::WidecardByte }; // 0x11
#define XX2 XX,XX       // WORD
#define XX4 XX2,XX2     // DWORD
#define XX8 XX4,XX4     // QWORD

// jichi 8/18/2013: Original maximum relative address in ITH
//enum { MAX_REL_ADDR = 0x200000 };

// jichi 10/1/2013: Increase relative address limit. Certain game engine like Artemis has larger code region
enum : DWORD { MAX_REL_ADDR = 0x00300000 };

static union {
  char text_buffer[0x1000];
  wchar_t wc_buffer[0x800];

  struct { // CodeSection
    DWORD base;
    DWORD size;
  } code_section[0x200];
};

char text_buffer_prev[0x1000];
DWORD buffer_index,
      buffer_length;

BOOL SafeFillRange(LPCWSTR dll, DWORD *lower, DWORD *upper)
{
  BOOL r = FALSE;
  ITH_WITH_SEH(r = FillRange(dll, lower, upper));
  return r;
}

// jichi 3/11/2014: The original FindEntryAligned function could raise exceptions without admin priv
DWORD SafeFindEntryAligned(DWORD start, DWORD back_range)
{
  DWORD r = 0;
  ITH_WITH_SEH(r = Util::FindEntryAligned(start, back_range));
  return r;
}

ULONG SafeFindEnclosingAlignedFunction(DWORD addr, DWORD range)
{
  ULONG r = 0;
  ITH_WITH_SEH(r = MemDbg::findEnclosingAlignedFunction(addr, range)); // this function might raise if failed
  return r;
}

ULONG SafeFindBytes(LPCVOID pattern, DWORD patternSize, DWORD lowerBound, DWORD upperBound)
{
  ULONG r = 0;
  ITH_WITH_SEH(r = MemDbg::findBytes(pattern, patternSize, lowerBound, upperBound));
  return r;
}

ULONG SafeMatchBytes(LPCVOID pattern, DWORD patternSize, DWORD lowerBound, DWORD upperBound, BYTE wildcard = XX)
{
  ULONG r = 0;
  ITH_WITH_SEH(r = MemDbg::matchBytes(pattern, patternSize, lowerBound, upperBound, wildcard));
  return r;
}

// jichi 7/17/2014: Search mapped memory for emulators
ULONG _SafeMatchBytesInMappedMemory(LPCVOID pattern, DWORD patternSize, BYTE wildcard,
                                   ULONG start, ULONG stop, ULONG step)
{
  for (ULONG i = start; i < stop; i += step) // + patternSize to avoid overlap
    if (ULONG r = SafeMatchBytes(pattern, patternSize, i, i + step + patternSize + 1, wildcard))
      return r;
  return 0;
}

inline ULONG SafeMatchBytesInGCMemory(LPCVOID pattern, DWORD patternSize)
{
  enum : ULONG {
    start = MemDbg::MappedMemoryStartAddress // 0x01000000
    , stop = MemDbg::MemoryStopAddress // 0x7ffeffff
    , step = start
  };
  return _SafeMatchBytesInMappedMemory(pattern, patternSize, XX, start, stop, step);
}

inline ULONG SafeMatchBytesInPSPMemory(LPCVOID pattern, DWORD patternSize, DWORD start = MemDbg::MappedMemoryStartAddress, DWORD stop = MemDbg::MemoryStopAddress)
{
  ULONG step = PPSSPP_VERSION[1] == 9 && PPSSPP_VERSION[2] == 8 ? PPSSPP_MEMORY_SEARCH_STEP_98 : PPSSPP_MEMORY_SEARCH_STEP_99;
  return _SafeMatchBytesInMappedMemory(pattern, patternSize, XX, start, stop, step);
}

inline ULONG SafeMatchBytesInPS2Memory(LPCVOID pattern, DWORD patternSize)
{
  // PCSX2 memory range
  // ds: begin from 0x20000000
  // cs: begin from 0x30000000
  enum : ULONG {
    //start = MemDbg::MappedMemoryStartAddress // 0x01000000
    start = 0x30000000 // larger than PSP to skip the garbage memory
    , stop = 0x40000000 // larger than PSP as PS2 has larger memory
    , step = 0x00010000 // smaller than PPS
    //, step = 0x00050000 // the same as PPS
    //, step = 0x1000 // step  must be at least 0x1000 (offset in SearchPattern)
  };
  return _SafeMatchBytesInMappedMemory(pattern, patternSize, XX, start, stop, step);
}

// 7/29/2014 jichi: I should move these functions to different files
// String utilities
// Return the address of the first non-zero address
LPCSTR reverse_search_begin(const char * s)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  if (*s)
    for (size_t i = 0; i < MAX_LENGTH; i++, s--)
      if (!*s)
        return s + 1;
  return nullptr;
}

bool all_ascii(const char *s)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  if (s)
    for (size_t i = 0; i < MAX_LENGTH && *s; i++, s--)
      if (*s < 0) // signed char
        return false;
  return true;
}

// String filters

void CharReplacer(char *str, size_t *size, char fr, char to)
{
  size_t len = *size;
  for (size_t i = 0; i < len; i++)
    if (str[i] == fr)
      str[i] = to;
}

void WideCharReplacer(wchar_t *str, size_t *size, wchar_t fr, wchar_t to)
{
  size_t len = *size / 2;
  for (size_t i = 0; i < len; i++)
    if (str[i] == fr)
      str[i] = to;
}

void CharFilter(char *str, size_t *size, char ch)
{
  size_t len = *size,
         curlen;
  char *cur = (char *)::memchr(str, ch, len);
  while (cur && --len &&
      (curlen = len - (cur - str))) {
    ::memmove(cur, cur + 1, curlen);
    cur = (char *)::memchr(cur, ch, curlen);
  }
  *size = len;
}

void WideCharFilter(wchar_t *str, size_t *size, wchar_t ch)
{
  size_t len = *size / 2,
         curlen;
  wchar_t *cur = cpp_wcsnchr(str, ch, len);
  while (cur && --len &&
      (curlen = len - (cur - str))) {
    ::memmove(cur, cur + 1, 2 * curlen);
    cur = cpp_wcsnchr(cur, ch, curlen);
  }
  *size = len * 2;
}

void CharsFilter(char *str, size_t *size, const char *chars)
{
  size_t len = *size,
         curlen;
  char *cur = cpp_strnpbrk(str, chars, len);
  while (cur && --len &&
      (curlen = len - (cur - str))) {
    ::memmove(cur, cur + 1, curlen);
    cur = cpp_strnpbrk(cur, chars, curlen);
  }
  *size = len;
}

void WideCharsFilter(wchar_t *str, size_t *size, const wchar_t *chars)
{
  size_t len = *size / 2,
         curlen;
  wchar_t *cur = cpp_wcsnpbrk(str, chars, len);
  while (cur && --len &&
      (curlen = len - (cur - str))) {
    ::memmove(cur, cur + 1, 2 * curlen);
    cur = cpp_wcsnpbrk(cur, chars, curlen);
  }
  *size = len * 2;
}

void StringFilter(char *str, size_t *size, const char *remove, size_t removelen)
{
  size_t len = *size,
         curlen;
  char *cur = cpp_strnstr(str, remove, len);
  while (cur &&
      (len -= removelen) &&
      (curlen = len - (cur - str))) {
    ::memmove(cur, cur + removelen, curlen);
    cur = cpp_strnstr(cur, remove, curlen);
  }
  *size = len;
}

void WideStringFilter(wchar_t *str, size_t *size, const wchar_t *remove, size_t removelen)
{
  size_t len = *size / 2,
         curlen;
  wchar_t *cur = cpp_wcsnstr(str, remove, len);
  while (cur &&
      (len -= removelen) &&
      (curlen = len - (cur - str))) {
    ::memmove(cur, cur + removelen, 2 * curlen);
    cur = cpp_wcsnstr(cur, remove, curlen);
  }
  *size = len * 2;
}
bool NewLineCharFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  CharFilter(reinterpret_cast<LPSTR>(data), reinterpret_cast<size_t *>(size),
      '\n');
  return true;
}
bool NewLineWideCharFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  CharFilter(reinterpret_cast<LPSTR>(data), reinterpret_cast<size_t *>(size),
      L'\n');
  return true;
}
bool NewLineStringFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  StringFilter(reinterpret_cast<LPSTR>(data), reinterpret_cast<size_t *>(size),
      "\\n", 2);
  return true;
}

bool NewLineCharToSpaceFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  CharReplacer(reinterpret_cast<LPSTR>(data), reinterpret_cast<size_t *>(size), '\n', ' ');
  return true;
}
bool NewLineWideCharToSpaceFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  WideCharReplacer(reinterpret_cast<LPWSTR>(data), reinterpret_cast<size_t *>(size), L'\n', L' ');
  return true;
}

// Remove every characters <= 0x1f (i.e. before space ' ') except 0xa and 0xd.
bool IllegalCharsFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  CharsFilter(reinterpret_cast<LPSTR>(data), reinterpret_cast<size_t *>(size),
      "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x12\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f");
  return true;
}
bool IllegalWideCharsFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  WideCharsFilter(reinterpret_cast<LPWSTR>(data), reinterpret_cast<size_t *>(size),
      L"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x12\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f");
  return true;
}

} // unnamed namespace

namespace Engine {

/********************************************************************************************
KiriKiri hook:
  Usually there are xp3 files in the game folder but also exceptions.
  Find TVP(KIRIKIRI) in the version description is a much more precise way.

  KiriKiri1 correspond to AGTH KiriKiri hook, but this doesn't always work well.
  Find call to GetGlyphOutlineW and go to function header. EAX will point to a
  structure contains character (at 0x14, [EAX+0x14]) we want. To split names into
  different threads AGTH uses [EAX], seems that this value stands for font size.
  Since KiriKiri is compiled by BCC and BCC fastcall uses EAX to pass the first
  parameter. Here we choose EAX is reasonable.
  KiriKiri2 is a redundant hook to catch text when 1 doesn't work. When this happens,
  usually there is a single GetTextExtentPoint32W contains irregular repetitions which
  is out of the scope of KS or KF. This time we find a point and split them into clean
  text threads. First find call to GetTextExtentPoint32W and step out of this function.
  Usually there is a small loop. It is this small loop messed up the text. We can find
  one ADD EBX,2 in this loop. It's clear that EBX is a string pointer goes through the
  string. After the loop EBX will point to the end of the string. So EBX-2 is the last
  char and we insert hook here to extract it.
********************************************************************************************/
#if 0 // jichi 11/12/2013: not used
static void SpecialHookKiriKiri(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD p1 =  *(DWORD *)(esp_base - 0x14),
        p2 =  *(DWORD *)(esp_base - 0x18);
  if ((p1>>16) == (p2>>16)) {
    if (DWORD p3 = *(DWORD *)p1) {
      p3 += 8;
      for (p2 = p3 + 2; *(WORD *)p2; p2 += 2);
      *len = p2 - p3;
      *data = p3;
      p1 = *(DWORD *)(esp_base - 0x20);
      p1 = *(DWORD *)(p1 + 0x74);
      *split = p1 | *(DWORD *)(esp_base + 0x48);
    } else
      *len = 0;
  } else
    *len=0;
}
#endif // 0

bool FindKiriKiriHook(DWORD fun, DWORD size, DWORD pt, DWORD flag) // jichi 10/20/2014: change return value to bool
{
  enum : DWORD {
    // jichi 10/20/2014: mov ebp,esp, sub esp,*
    kirikiri1_sig = 0xec8b55,

    // jichi 10/20/2014:
    // 00e01542   53               push ebx
    // 00e01543   56               push esi
    // 00e01544   57               push edi
    kirikiri2_sig = 0x575653
  };
  enum : DWORD { StartAddress = 0x1000 };
  enum : DWORD { StartRange = 0x6000, StopRange = 0x8000 }; // jichi 10/20/2014: ITH original pattern range

  // jichi 10/20/2014: The KiriKiri patterns exist in multiple places of the game.
  //enum : DWORD { StartRange = 0x8000, StopRange = 0x9000 }; // jichi 10/20/2014: change to a different range

  //WCHAR str[0x40];
  DWORD sig = flag ? kirikiri2_sig : kirikiri1_sig;
  DWORD t = 0;
  for (DWORD i = StartAddress; i < size - 4; i++)
    if (*(WORD *)(pt + i) == 0x15ff) { // jichi 10/20/2014: call dword ptr ds
      DWORD addr = *(DWORD *)(pt + i + 2);

      // jichi 10/20/2014: There are multiple function calls. The flag+1 one is selected.
      // i.e. KiriKiri1: The first call to GetGlyphOutlineW is selected
      //      KiriKiri2: The second call to GetTextExtentPoint32W is selected
      if (addr >= pt && addr <= pt + size - 4
          && *(DWORD *)addr == fun)
        t++;
      if (t == flag + 1)  // We find call to GetGlyphOutlineW or GetTextExtentPoint32W.
        //swprintf(str, L"CALL addr:0x%.8X",i+pt);
        //ConsoleOutput(str);
        for (DWORD j = i; j > i - StartAddress; j--)
          if (((*(DWORD *)(pt + j)) & 0xffffff) == sig) {
            if (flag)  { // We find the function entry. flag indicate 2 hooks.
              t = 0;  // KiriKiri2, we need to find call to this function.
              for (DWORD k = j + StartRange; k < j + StopRange; k++) // Empirical range.
                if (*(BYTE *)(pt + k) == 0xe8) {
                  if (k + 5 + *(DWORD *)(pt + k + 1) == j)
                    t++;
                  if (t == 2) {
                    //for (k+=pt+0x14; *(WORD*)(k)!=0xC483;k++);
                    //swprintf(str, L"Hook addr: 0x%.8X",pt+k);
                    //ConsoleOutput(str);
                    HookParam hp = {};
                    hp.addr = pt + k + 0x14;
                    hp.off = -0x14;
                    hp.ind = -0x2;
                    hp.split = -0xc;
                    hp.length_offset = 1;
                    hp.type = USING_UNICODE|NO_CONTEXT|USING_SPLIT|DATA_INDIRECT;
                    ConsoleOutput("vnreng: INSERT KiriKiri2");
                    NewHook(hp, L"KiriKiri2");
                    return true;
                  }
                }
            } else {
              //swprintf(str, L"Hook addr: 0x%.8X",pt+j);
              //ConsoleOutput(str);
              HookParam hp = {};
              hp.addr = (DWORD)pt + j;
              hp.off = -0x8;
              hp.ind = 0x14;
              hp.split = -0x8;
              hp.length_offset = 1;
              hp.type = USING_UNICODE|DATA_INDIRECT|USING_SPLIT|SPLIT_INDIRECT;
              ConsoleOutput("vnreng: INSERT KiriKiri1");
              NewHook(hp, L"KiriKiri1");
              return true;
            }
            return false;
          }
        //ConsoleOutput("vnreng:KiriKiri: FAILED to find function entry");
    }
  if (flag)
    ConsoleOutput("vnreng:KiriKiri2: failed");
  else
    ConsoleOutput("vnreng:KiriKiri1: failed");
  return false;
}

bool InsertKiriKiriHook() // 9/20/2014 jichi: change return type to bool
{
  bool k1 = FindKiriKiriHook((DWORD)GetGlyphOutlineW,      module_limit_ - module_base_, module_base_, 0), // KiriKiri1
       k2 = FindKiriKiriHook((DWORD)GetTextExtentPoint32W, module_limit_ - module_base_, module_base_, 1); // KiriKiri2
  //RegisterEngineType(ENGINE_KIRIKIRI);
  if (k1 && k2) {
    ConsoleOutput("vnreng:KiriKiri1: disable GDI hooks");
    DisableGDIHooks();
  }
  return k1 || k2;
}

/** 10/20/2014 jichi: KAGParser
 *  Sample game: [141128] Venus Blood -HYPNO- ヴィーナスブラッド・ヒュプノ 体験版
 *
 *  drawText and drawGlyph seem to be the right function to look at.
 *  However, the latest source code does not match VenusBlood.
 *
 *  Debug method:
 *  Pre-compute: hexstr 視界のきかない utf16, got: 96894c756e304d304b306a304430
 *  Use ollydbg to insert hardware break point before the scene is entered.
 *  It found several places either in game or KAGParser, and the last one is as follows.
 *  It tries to find "[" (0x5b) in the memory.
 *
 *  1. It cannot find character name.
 *  2. It will extract [r].
 *
 *  6e562270   75 0a            jnz short kagparse.6e56227c
 *  6e562272   c705 00000000 00>mov dword ptr ds:[0],0x0
 *  6e56227c   ffb424 24010000  push dword ptr ss:[esp+0x124]
 *  6e562283   ff9424 24010000  call dword ptr ss:[esp+0x124]
 *  6e56228a   8b8c24 20010000  mov ecx,dword ptr ss:[esp+0x120]
 *  6e562291   890d 14ed576e    mov dword ptr ds:[0x6e57ed14],ecx
 *  6e562297   68 3090576e      push kagparse.6e579030                   ; unicode "[r]"
 *  6e56229c   8d46 74          lea eax,dword ptr ds:[esi+0x74]
 *  6e56229f   50               push eax
 *  6e5622a0   ffd1             call ecx
 *  6e5622a2   8b4e 50          mov ecx,dword ptr ds:[esi+0x50]
 *  6e5622a5   8b46 54          mov eax,dword ptr ds:[esi+0x54]
 *  6e5622a8   66:833c48 5b     cmp word ptr ds:[eax+ecx*2],0x5b ; jichi: hook here
 *  6e5622ad   75 06            jnz short kagparse.6e5622b5
 *  6e5622af   8d41 01          lea eax,dword ptr ds:[ecx+0x1]
 *  6e5622b2   8946 50          mov dword ptr ds:[esi+0x50],eax
 *  6e5622b5   ff46 50          inc dword ptr ds:[esi+0x50]
 *  6e5622b8  ^e9 aebcffff      jmp kagparse.6e55df6b
 *  6e5622bd   8d8c24 88030000  lea ecx,dword ptr ss:[esp+0x388]
 *  6e5622c4   e8 b707ffff      call kagparse.6e552a80
 *  6e5622c9   84c0             test al,al
 *  6e5622cb   75 0f            jnz short kagparse.6e5622dc
 *  6e5622cd   8d8424 88030000  lea eax,dword ptr ss:[esp+0x388]
 *  6e5622d4   50               push eax
 *  6e5622d5   8bce             mov ecx,esi
 *  6e5622d7   e8 149bffff      call kagparse.6e55bdf0
 *  6e5622dc   8d8c24 80030000  lea ecx,dword ptr ss:[esp+0x380]
 *  6e5622e3   e8 9807ffff      call kagparse.6e552a80
 *  6e5622e8   84c0             test al,al
 *  6e5622ea   75 0f            jnz short kagparse.6e5622fb
 *  6e5622ec   8d8424 80030000  lea eax,dword ptr ss:[esp+0x380]
 *  6e5622f3   50               push eax
 *  6e5622f4   8bce             mov ecx,esi
 *  6e5622f6   e8 35a0ffff      call kagparse.6e55c330
 *  6e5622fb   8d8c24 c0030000  lea ecx,dword ptr ss:[esp+0x3c0]
 *  6e562302   c68424 c0040000 >mov byte ptr ss:[esp+0x4c0],0x3c
 *  6e56230a   e8 81edfeff      call kagparse.6e551090
 *  6e56230f   8d8c24 80030000  lea ecx,dword ptr ss:[esp+0x380]
 *  6e562316   c68424 c0040000 >mov byte ptr ss:[esp+0x4c0],0x3b
 *  6e56231e   e8 8deefeff      call kagparse.6e5511b0
 *  6e562323   8d8c24 88030000  lea ecx,dword ptr ss:[esp+0x388]
 *  6e56232a   e9 d7000000      jmp kagparse.6e562406
 *  6e56232f   66:837c24 20 00  cmp word ptr ss:[esp+0x20],0x0
 *  6e562335   75 10            jnz short kagparse.6e562347
 *  6e562337   ff46 4c          inc dword ptr ds:[esi+0x4c]
 *  6e56233a   c746 50 00000000 mov dword ptr ds:[esi+0x50],0x0
 *  6e562341   c646 5c 00       mov byte ptr ds:[esi+0x5c],0x0
 *
 *  Runtime regisers:
 *  EAX 09C1A626    text address
 *  ECX 00000000    0 or other offset
 *  EDX 025F1368    this value seems does not change. it is always pointed to 0
 *  EBX 0000300C
 *  ESP 0029EB7C
 *  EBP 0029F044
 *  ESI 04EE4150
 *  EDI 0029F020
 *
 *  とな恋 KAGParserEx.dll
 *  10013948   68 14830210      push _3.10028314                         ; UNICODE "[r]"
 *  1001394d   83c2 7c          add edx,0x7c
 *  10013950   52               push edx
 *  10013951   ffd0             call eax
 *  10013953   8b75 08          mov esi,dword ptr ss:[ebp+0x8]
 *  10013956   eb 02            jmp short _3.1001395a
 *  10013958   8bf2             mov esi,edx
 *  1001395a   8b46 58          mov eax,dword ptr ds:[esi+0x58]
 *  1001395d   8b4e 5c          mov ecx,dword ptr ds:[esi+0x5c]
 *  10013960   66:833c41 5b     cmp word ptr ds:[ecx+eax*2],0x5b    ; jichi: hook here
 *  10013965   75 06            jnz short _3.1001396d
 *  10013967   83c0 01          add eax,0x1
 *  1001396a   8946 58          mov dword ptr ds:[esi+0x58],eax
 *  1001396d   8346 58 01       add dword ptr ds:[esi+0x58],0x1
 *  10013971   807e 7a 00       cmp byte ptr ds:[esi+0x7a],0x0
 *  10013975  ^0f85 b5a7ffff    jnz _3.1000e130
 *  1001397b   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  1001397e   83b8 90000000 ff cmp dword ptr ds:[eax+0x90],-0x1
 *  10013985   0f84 68040000    je _3.10013df3
 *  1001398b   8bd8             mov ebx,eax
 *  1001398d  ^e9 a1a7ffff      jmp _3.1000e133
 *  10013992   8d7c24 78        lea edi,dword ptr ss:[esp+0x78]
 *  10013996   8d7424 54        lea esi,dword ptr ss:[esp+0x54]
 *  1001399a   e8 e16fffff      call _3.1000a980
 */

#if 0 // not used, as KiriKiriZ is sufficient, and most KiriKiriZ games use KAGParserEx instead of KAGParser.
namespace { // unnamed

bool KAGParserFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  WideStringFilter(reinterpret_cast<LPWSTR>(data), reinterpret_cast<size_t *>(size),
                          L"[r]", 3);
  return true;
}

void SpecialHookKAGParser(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  // 6e5622a8   66:833c48 5b     cmp word ptr ds:[eax+ecx*2],0x5b
  DWORD eax = regof(eax, esp_base),
        ecx = regof(ecx, esp_base);
  if (eax && !ecx) { // skip string when ecx is not zero
    *data = eax;
    *len = ::wcslen((LPCWSTR)eax) * 2; // 2 == sizeof(wchar_t)
    *split = FIXED_SPLIT_VALUE; // merge all threads
  }
}

void SpecialHookKAGParserEx(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  // 10013960   66:833c41 5b     cmp word ptr ds:[ecx+eax*2],0x5b
  DWORD eax = regof(eax, esp_base),
        ecx = regof(ecx, esp_base);
  if (ecx && !eax) { // skip string when ecx is not zero
    *data = ecx;
    *len = ::wcslen((LPCWSTR)ecx) * 2; // 2 == sizeof(wchar_t)
    *split = FIXED_SPLIT_VALUE; // merge all threads
  }
}
} // unnamed namespace
bool InsertKAGParserHook()
{
  ULONG startAddress, stopAddress;
  if (!NtInspect::getModuleMemoryRange(L"KAGParser.dll", &startAddress, &stopAddress)) {
    ConsoleOutput("vnreng:KAGParser: failed to get memory range");
    return false;
  }
  const wchar_t *patternString = L"[r]";
  const size_t patternStringSize = ::wcslen(patternString) * 2;
  ULONG addr = MemDbg::findBytes(patternString, patternStringSize, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:KAGParser: [r] global string not found");
    return false;
  }
  // Find where it is used as function parameter
  addr = MemDbg::findPushAddress(addr, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:KAGParser: push address not found");
    return false;
  }

  const BYTE ins[] = {
    0x66,0x83,0x3c,0x48, 0x5b // 6e5622a8   66:833c48 5b   cmp word ptr ds:[eax+ecx*2],0x5b ; jichi: hook here
  };
  enum { range = 0x20 }; // 0x6e5622a8 - 0x6e562297 = 17
  addr = MemDbg::findBytes(ins, sizeof(ins), addr, addr + range);
  if (!addr) {
    ConsoleOutput("vnreng:KAGParser: instruction pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.text_fun = SpecialHookKAGParser;
  hp.filter_fun = KAGParserFilter;
  hp.type = USING_UNICODE|FIXING_SPLIT|NO_CONTEXT; // Fix the split value to merge all threads
  ConsoleOutput("vnreng: INSERT KAGParser");
  NewHook(hp, L"KAGParser");
  return true;
}
bool InsertKAGParserExHook()
{
  ULONG startAddress, stopAddress;
  if (!NtInspect::getModuleMemoryRange(L"KAGParserEx.dll", &startAddress, &stopAddress)) {
    ConsoleOutput("vnreng:KAGParserEx: failed to get memory range");
    return false;
  }
  const wchar_t *patternString = L"[r]";
  const size_t patternStringSize = ::wcslen(patternString) * 2;
  ULONG addr = MemDbg::findBytes(patternString, patternStringSize, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:KAGParserEx: [r] global string not found");
    return false;
  }
  // Find where it is used as function parameter
  addr = MemDbg::findPushAddress(addr, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:KAGParserEx: push address not found");
    return false;
  }

  const BYTE ins[] = {
    0x66,0x83,0x3c,0x41, 0x5b // 10013960   66:833c41 5b     cmp word ptr ds:[ecx+eax*2],0x5b    ; jichi: hook here
  };
  enum { range = 0x20 }; // 0x10013960 - 0x10013948 = 24
  addr = MemDbg::findBytes(ins, sizeof(ins), addr, addr + range);
  if (!addr) {
    ConsoleOutput("vnreng:KAGParserEx: instruction pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.text_fun = SpecialHookKAGParserEx;
  hp.filter_fun = KAGParserFilter;
  hp.type = USING_UNICODE|FIXING_SPLIT|NO_CONTEXT; // Fix the split value to merge all threads
  ConsoleOutput("vnreng: INSERT KAGParserEx");
  NewHook(hp, L"KAGParserEx");
  return true;
}
#endif // 0

/** 10/24/2014 jichi: New KiriKiri hook
 *  Sample game: [141128] Venus Blood -HYPNO- ヴィーナスブラッド・ヒュプノ 体験版
 *
 *  This engine will hook to the caller of caller of the first GetGlyphOutlineW (totally three).
 *  The logic is quite similar to KiriKiri1 except it backtrack twice to get the function call.
 *
 *  1/31/2015: If the game no longer invoke GDI functions by default, one way to find the hook
 *  is to click the フォント in the menu to force triggering GetGlyphOutlineW function.
 *
 *  KiriKiriZ:
 *  https://github.com/krkrz/krkrz
 *  http://krkrz.github.io
 *
 *  KiriKiri API: http://devdoc.kikyou.info/tvp/docs/kr2doc/contents/f_Layer.html
 *
 *  See: krkrz/src/core/visual/LayerIntf.cpp
 *  API: http://devdoc.kikyou.info/tvp/docs/kr2doc/contents/f_Layer_drawText.html
 *
 *  Debug method:
 *  Backtrack from GetGlyphOutlineW, and find the first function that is invoked more
 *  times than (cached) GetGlyphOutlineW.
 *
 *  - Find function calls to GetGlyphOutlineW (totally three)
 *
 *  - Find the caller of the first GetGlyphOutlineW
 *    Using MemDbg::findCallerAddressAfterInt3()
 *
 *  - Find the caller of the above caller
 *    Since the function address is dynamic, the function is found using KiriKiriZHook
 *
 *    00377c44   8b01             mov eax,dword ptr ds:[ecx]
 *    00377c46   ff75 10          push dword ptr ss:[ebp+0x10]
 *    00377c49   ff75 0c          push dword ptr ss:[ebp+0xc]
 *    00377c4c   53               push ebx
 *    00377c4d   ff50 1c          call dword ptr ds:[eax+0x1c] ; jichi: called here
 *    00377c50   8bf0             mov esi,eax
 *    00377c52   8975 e4          mov dword ptr ss:[ebp-0x1c],esi
 *    00377c55   ff46 04          inc dword ptr ds:[esi+0x4]
 *    00377c58   c745 fc 04000000 mov dword ptr ss:[ebp-0x4],0x4
 *
 *  Then, the UTF8 two-byte character is at [ecx]+0x14
 *    0017E950  16 00 00 00 00 02 00 00 00 00 00 00 98 D2 76 02
 *    0017E960  E0 8E 90 D9 42 7D 00 00 00 02 00 00 01 00 00 00
 *                          up: text here
 *    0017E970  01 00 01 FF 00 00 00 00 00 00 00 00 C8
 *
 *  1/30/2015:
 *  The hooked function in Venus Blood -HYPNO- is as follows.
 *  Since サノバウィッチ (150226), KiriKiriZ no longer invokes GetGlyphOutlineW.
 *  Try to extract instruction patterns from the following function instead.
 *
 *  011a7a3c   cc               int3
 *  011a7a3d   cc               int3
 *  011a7a3e   cc               int3
 *  011a7a3f   cc               int3
 *  011a7a40   55               push ebp
 *  011a7a41   8bec             mov ebp,esp
 *  011a7a43   6a ff            push -0x1
 *  011a7a45   68 dbaa3101      push .0131aadb
 *  011a7a4a   64:a1 00000000   mov eax,dword ptr fs:[0]
 *  011a7a50   50               push eax
 *  011a7a51   83ec 14          sub esp,0x14
 *  011a7a54   53               push ebx
 *  011a7a55   56               push esi
 *  011a7a56   57               push edi
 *  011a7a57   a1 00593d01      mov eax,dword ptr ds:[0x13d5900]
 *  011a7a5c   33c5             xor eax,ebp
 *  011a7a5e   50               push eax
 *  011a7a5f   8d45 f4          lea eax,dword ptr ss:[ebp-0xc]
 *  011a7a62   64:a3 00000000   mov dword ptr fs:[0],eax
 *  011a7a68   8965 f0          mov dword ptr ss:[ebp-0x10],esp
 *  011a7a6b   8bd9             mov ebx,ecx
 *  011a7a6d   803d 00113e01 00 cmp byte ptr ds:[0x13e1100],0x0
 *  011a7a74   75 17            jnz short .011a7a8d
 *  011a7a76   c745 e8 1cb83d01 mov dword ptr ss:[ebp-0x18],.013db81c
 *  011a7a7d   8d45 e8          lea eax,dword ptr ss:[ebp-0x18]
 *  011a7a80   50               push eax
 *  011a7a81   e8 4ae2f0ff      call .010b5cd0
 *  011a7a86   c605 00113e01 01 mov byte ptr ds:[0x13e1100],0x1
 *  011a7a8d   33c9             xor ecx,ecx
 *  011a7a8f   384b 21          cmp byte ptr ds:[ebx+0x21],cl
 *  011a7a92   0f95c1           setne cl
 *  011a7a95   33c0             xor eax,eax
 *  011a7a97   3843 20          cmp byte ptr ds:[ebx+0x20],al
 *  011a7a9a   0f95c0           setne al
 *  011a7a9d   33c8             xor ecx,eax
 *  011a7a9f   334b 10          xor ecx,dword ptr ds:[ebx+0x10]
 *  011a7aa2   0fb743 14        movzx eax,word ptr ds:[ebx+0x14]
 *  011a7aa6   33c8             xor ecx,eax
 *  011a7aa8   8b7b 1c          mov edi,dword ptr ds:[ebx+0x1c]
 *  011a7aab   33f9             xor edi,ecx
 *  011a7aad   337b 18          xor edi,dword ptr ds:[ebx+0x18]
 *  011a7ab0   897d e4          mov dword ptr ss:[ebp-0x1c],edi
 *  011a7ab3   57               push edi
 *  011a7ab4   53               push ebx
 *  011a7ab5   e8 06330000      call .011aadc0
 *  011a7aba   8bf0             mov esi,eax
 *  011a7abc   85f6             test esi,esi
 *  011a7abe   74 26            je short .011a7ae6
 *  011a7ac0   56               push esi
 *  011a7ac1   e8 ba330000      call .011aae80
 *  011a7ac6   8d46 2c          lea eax,dword ptr ds:[esi+0x2c]
 *  011a7ac9   85c0             test eax,eax
 *  011a7acb   74 19            je short .011a7ae6
 *  011a7acd   8b08             mov ecx,dword ptr ds:[eax]
 *  011a7acf   ff41 04          inc dword ptr ds:[ecx+0x4]
 *  011a7ad2   8b00             mov eax,dword ptr ds:[eax]
 *  011a7ad4   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  011a7ad7   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  011a7ade   59               pop ecx
 *  011a7adf   5f               pop edi
 *  011a7ae0   5e               pop esi
 *  011a7ae1   5b               pop ebx
 *  011a7ae2   8be5             mov esp,ebp
 *  011a7ae4   5d               pop ebp
 *  011a7ae5   c3               retn
 *  011a7ae6   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 *  011a7ae9   85c9             test ecx,ecx
 *  011a7aeb   0f84 47010000    je .011a7c38
 *  011a7af1   0fb743 14        movzx eax,word ptr ds:[ebx+0x14]
 *  011a7af5   50               push eax
 *  011a7af6   e8 b5090300      call .011d84b0
 *  011a7afb   8bf0             mov esi,eax
 *  011a7afd   8975 ec          mov dword ptr ss:[ebp-0x14],esi
 *  011a7b00   85f6             test esi,esi
 *  011a7b02   0f84 30010000    je .011a7c38
 *  011a7b08   6a 34            push 0x34
 *  011a7b0a   e8 29621300      call .012ddd38
 *  011a7b0f   83c4 04          add esp,0x4
 *  011a7b12   8bf8             mov edi,eax
 *  011a7b14   897d e0          mov dword ptr ss:[ebp-0x20],edi
 *  011a7b17   c745 fc 00000000 mov dword ptr ss:[ebp-0x4],0x0
 *  011a7b1e   85ff             test edi,edi
 *  011a7b20   74 1d            je short .011a7b3f
 *  011a7b22   c747 2c 41000000 mov dword ptr ds:[edi+0x2c],0x41
 *  011a7b29   c647 32 00       mov byte ptr ds:[edi+0x32],0x0
 *  011a7b2d   c747 04 01000000 mov dword ptr ds:[edi+0x4],0x1
 *  011a7b34   c707 00000000    mov dword ptr ds:[edi],0x0
 *  011a7b3a   8945 e8          mov dword ptr ss:[ebp-0x18],eax
 *  011a7b3d   eb 05            jmp short .011a7b44
 *  011a7b3f   33ff             xor edi,edi
 *  011a7b41   897d e8          mov dword ptr ss:[ebp-0x18],edi
 *  011a7b44   c745 fc ffffffff mov dword ptr ss:[ebp-0x4],-0x1
 *  011a7b4b   0fb746 04        movzx eax,word ptr ds:[esi+0x4]
 *  011a7b4f   8947 1c          mov dword ptr ds:[edi+0x1c],eax
 *  011a7b52   0fb746 06        movzx eax,word ptr ds:[esi+0x6]
 *  011a7b56   8947 20          mov dword ptr ds:[edi+0x20],eax
 *  011a7b59   0fbf46 0c        movsx eax,word ptr ds:[esi+0xc]
 *  011a7b5d   8947 10          mov dword ptr ds:[edi+0x10],eax
 *  011a7b60   0fbf46 0e        movsx eax,word ptr ds:[esi+0xe]
 *  011a7b64   8947 14          mov dword ptr ds:[edi+0x14],eax
 *  011a7b67   0fbf46 08        movsx eax,word ptr ds:[esi+0x8]
 *  011a7b6b   0345 0c          add eax,dword ptr ss:[ebp+0xc]
 *  011a7b6e   8947 08          mov dword ptr ds:[edi+0x8],eax
 *  011a7b71   0fbf46 0a        movsx eax,word ptr ds:[esi+0xa]
 *  011a7b75   8b4d 10          mov ecx,dword ptr ss:[ebp+0x10]
 *  011a7b78   2bc8             sub ecx,eax
 *  011a7b7a   894f 0c          mov dword ptr ds:[edi+0xc],ecx
 *  011a7b7d   0fb643 20        movzx eax,byte ptr ds:[ebx+0x20]
 *  011a7b81   8847 30          mov byte ptr ds:[edi+0x30],al
 *  011a7b84   c647 32 00       mov byte ptr ds:[edi+0x32],0x0
 *  011a7b88   0fb643 21        movzx eax,byte ptr ds:[ebx+0x21]
 *  011a7b8c   8847 31          mov byte ptr ds:[edi+0x31],al
 *  011a7b8f   8b43 1c          mov eax,dword ptr ds:[ebx+0x1c]
 *  011a7b92   8947 28          mov dword ptr ds:[edi+0x28],eax
 *  011a7b95   8b43 18          mov eax,dword ptr ds:[ebx+0x18]
 *  011a7b98   8947 24          mov dword ptr ds:[edi+0x24],eax
 *  011a7b9b   c745 fc 01000000 mov dword ptr ss:[ebp-0x4],0x1
 *  011a7ba2   837f 1c 00       cmp dword ptr ds:[edi+0x1c],0x0
 *  011a7ba6   74 64            je short .011a7c0c
 *  011a7ba8   8b47 20          mov eax,dword ptr ds:[edi+0x20]
 *  011a7bab   85c0             test eax,eax
 *  011a7bad   74 5d            je short .011a7c0c
 *  011a7baf   0fb776 04        movzx esi,word ptr ds:[esi+0x4]
 *  011a7bb3   4e               dec esi
 *  011a7bb4   83e6 fc          and esi,0xfffffffc
 *  011a7bb7   83c6 04          add esi,0x4
 *  011a7bba   8977 18          mov dword ptr ds:[edi+0x18],esi
 *  011a7bbd   0fafc6           imul eax,esi
 *  011a7bc0   50               push eax
 *  011a7bc1   8bcf             mov ecx,edi
 *  011a7bc3   e8 b8f6ffff      call .011a7280
 *  011a7bc8   56               push esi
 *  011a7bc9   ff37             push dword ptr ds:[edi]
 *  011a7bcb   ff75 ec          push dword ptr ss:[ebp-0x14]
 *  011a7bce   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 *  011a7bd1   e8 3a090300      call .011d8510
 *  011a7bd6   807b 21 00       cmp byte ptr ds:[ebx+0x21],0x0
 *  011a7bda   74 0d            je short .011a7be9
 *  011a7bdc   ff77 28          push dword ptr ds:[edi+0x28]
 *  011a7bdf   ff77 24          push dword ptr ds:[edi+0x24]
 *  011a7be2   8bcf             mov ecx,edi
 *  011a7be4   e8 d70affff      call .011986c0
 *  011a7be9   897d ec          mov dword ptr ss:[ebp-0x14],edi
 *  011a7bec   ff47 04          inc dword ptr ds:[edi+0x4]
 *  011a7bef   c645 fc 02       mov byte ptr ss:[ebp-0x4],0x2
 *  011a7bf3   8d45 ec          lea eax,dword ptr ss:[ebp-0x14]
 *  011a7bf6   50               push eax
 *  011a7bf7   ff75 e4          push dword ptr ss:[ebp-0x1c]
 *  011a7bfa   53               push ebx
 *  011a7bfb   e8 50280000      call .011aa450
 *  011a7c00   c645 fc 01       mov byte ptr ss:[ebp-0x4],0x1
 *  011a7c04   8d4d ec          lea ecx,dword ptr ss:[ebp-0x14]
 *  011a7c07   e8 84280000      call .011aa490
 *  011a7c0c   c745 fc ffffffff mov dword ptr ss:[ebp-0x4],-0x1
 *  011a7c13   8bc7             mov eax,edi
 *  011a7c15   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  011a7c18   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  011a7c1f   59               pop ecx
 *  011a7c20   5f               pop edi
 *  011a7c21   5e               pop esi
 *  011a7c22   5b               pop ebx
 *  011a7c23   8be5             mov esp,ebp
 *  011a7c25   5d               pop ebp
 *  011a7c26   c3               retn
 *  011a7c27   8b4d e8          mov ecx,dword ptr ss:[ebp-0x18]
 *  011a7c2a   e8 81f6ffff      call .011a72b0
 *  011a7c2f   6a 00            push 0x0
 *  011a7c31   6a 00            push 0x0
 *  011a7c33   e8 93cb1300      call .012e47cb
 *  011a7c38   a1 dc8a3d01      mov eax,dword ptr ds:[0x13d8adc]
 *  011a7c3d   8b0c85 88b93f01  mov ecx,dword ptr ds:[eax*4+0x13fb988]
 *  011a7c44   8b01             mov eax,dword ptr ds:[ecx]
 *  011a7c46   ff75 10          push dword ptr ss:[ebp+0x10]
 *  011a7c49   ff75 0c          push dword ptr ss:[ebp+0xc]
 *  011a7c4c   53               push ebx
 *  011a7c4d   ff50 1c          call dword ptr ds:[eax+0x1c]
 *  011a7c50   8bf0             mov esi,eax
 *  011a7c52   8975 e4          mov dword ptr ss:[ebp-0x1c],esi
 *  011a7c55   ff46 04          inc dword ptr ds:[esi+0x4]
 *  011a7c58   c745 fc 04000000 mov dword ptr ss:[ebp-0x4],0x4
 *  011a7c5f   8d45 e4          lea eax,dword ptr ss:[ebp-0x1c]
 *  011a7c62   50               push eax
 *  011a7c63   57               push edi
 *  011a7c64   53               push ebx
 *  011a7c65   e8 a62c0000      call .011aa910
 *  011a7c6a   a1 388b3f01      mov eax,dword ptr ds:[0x13f8b38]
 *  011a7c6f   8b0d 448b3f01    mov ecx,dword ptr ds:[0x13f8b44]
 *  011a7c75   3bc1             cmp eax,ecx
 *  011a7c77   76 08            jbe short .011a7c81
 *  011a7c79   2bc1             sub eax,ecx
 *  011a7c7b   50               push eax
 *  011a7c7c   e8 1f2e0000      call .011aaaa0
 *  011a7c81   c745 fc ffffffff mov dword ptr ss:[ebp-0x4],-0x1
 *  011a7c88   8b46 04          mov eax,dword ptr ds:[esi+0x4]
 *  011a7c8b   83f8 01          cmp eax,0x1
 *  011a7c8e   75 2c            jnz short .011a7cbc
 *  011a7c90   8b06             mov eax,dword ptr ds:[esi]
 *  011a7c92   85c0             test eax,eax
 *  011a7c94   74 09            je short .011a7c9f
 *  011a7c96   50               push eax
 *  011a7c97   e8 3b621300      call .012dded7
 *  011a7c9c   83c4 04          add esp,0x4
 *  011a7c9f   56               push esi
 *  011a7ca0   e8 335e1300      call .012ddad8
 *  011a7ca5   83c4 04          add esp,0x4
 *  011a7ca8   8bc6             mov eax,esi
 *  011a7caa   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  011a7cad   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  011a7cb4   59               pop ecx
 *  011a7cb5   5f               pop edi
 *  011a7cb6   5e               pop esi
 *  011a7cb7   5b               pop ebx
 *  011a7cb8   8be5             mov esp,ebp
 *  011a7cba   5d               pop ebp
 *  011a7cbb   c3               retn
 *  011a7cbc   48               dec eax
 *  011a7cbd   8946 04          mov dword ptr ds:[esi+0x4],eax
 *  011a7cc0   8bc6             mov eax,esi
 *  011a7cc2   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  011a7cc5   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  011a7ccc   59               pop ecx
 *  011a7ccd   5f               pop edi
 *  011a7cce   5e               pop esi
 *  011a7ccf   5b               pop ebx
 *  011a7cd0   8be5             mov esp,ebp
 *  011a7cd2   5d               pop ebp
 *  011a7cd3   c3               retn
 *  011a7cd4   cc               int3
 *  011a7cd5   cc               int3
 *  011a7cd6   cc               int3
 *  011a7cd7   cc               int3
 *  011a7cd8   cc               int3
 *
 *  Here's the hooked function in サノバウィッチ (150226).
 *  I randomly picked a pattern from VBH:
 *
 *    011a7a95   33c0             xor eax,eax
 *    011a7a97   3843 20          cmp byte ptr ds:[ebx+0x20],al
 *    011a7a9a   0f95c0           setne al
 *    011a7a9d   33c8             xor ecx,eax
 *    011a7a9f   334b 10          xor ecx,dword ptr ds:[ebx+0x10]
 *    011a7aa2   0fb743 14        movzx eax,word ptr ds:[ebx+0x14]
 *
 *  i.e: 33c03843200f95c033c8334b100fb74314
 *
 *  The new hooked function in サノバウィッチ is as follows.
 *
 *  012280dc   cc               int3
 *  012280dd   cc               int3
 *  012280de   cc               int3
 *  012280df   cc               int3
 *  012280e0   55               push ebp
 *  012280e1   8bec             mov ebp,esp
 *  012280e3   6a ff            push -0x1
 *  012280e5   68 3b813d01      push .013d813b
 *  012280ea   64:a1 00000000   mov eax,dword ptr fs:[0]
 *  012280f0   50               push eax
 *  012280f1   83ec 14          sub esp,0x14
 *  012280f4   53               push ebx
 *  012280f5   56               push esi
 *  012280f6   57               push edi
 *  012280f7   a1 00694901      mov eax,dword ptr ds:[0x1496900]
 *  012280fc   33c5             xor eax,ebp
 *  012280fe   50               push eax
 *  012280ff   8d45 f4          lea eax,dword ptr ss:[ebp-0xc]
 *  01228102   64:a3 00000000   mov dword ptr fs:[0],eax
 *  01228108   8965 f0          mov dword ptr ss:[ebp-0x10],esp
 *  0122810b   8bd9             mov ebx,ecx
 *  0122810d   803d e82d4a01 00 cmp byte ptr ds:[0x14a2de8],0x0
 *  01228114   75 17            jnz short .0122812d
 *  01228116   c745 e8 d8d44901 mov dword ptr ss:[ebp-0x18],.0149d4d8
 *  0122811d   8d45 e8          lea eax,dword ptr ss:[ebp-0x18]
 *  01228120   50               push eax
 *  01228121   e8 aadbf0ff      call .01135cd0
 *  01228126   c605 e82d4a01 01 mov byte ptr ds:[0x14a2de8],0x1
 *  0122812d   33c9             xor ecx,ecx
 *  0122812f   384b 21          cmp byte ptr ds:[ebx+0x21],cl
 *  01228132   0f95c1           setne cl
 *  01228135   33c0             xor eax,eax
 *  01228137   3843 20          cmp byte ptr ds:[ebx+0x20],al
 *  0122813a   0f95c0           setne al
 *  0122813d   33c8             xor ecx,eax
 *  0122813f   334b 10          xor ecx,dword ptr ds:[ebx+0x10]
 *  01228142   0fb743 14        movzx eax,word ptr ds:[ebx+0x14]
 *  01228146   33c8             xor ecx,eax
 *  01228148   8b7b 1c          mov edi,dword ptr ds:[ebx+0x1c]
 *  0122814b   33f9             xor edi,ecx
 *  0122814d   337b 18          xor edi,dword ptr ds:[ebx+0x18]
 *  01228150   897d e4          mov dword ptr ss:[ebp-0x1c],edi
 *  01228153   57               push edi
 *  01228154   53               push ebx
 *  01228155   e8 06330000      call .0122b460
 *  0122815a   8bf0             mov esi,eax
 *  0122815c   85f6             test esi,esi
 *  0122815e   74 26            je short .01228186
 *  01228160   56               push esi
 *  01228161   e8 ba330000      call .0122b520
 *  01228166   8d46 2c          lea eax,dword ptr ds:[esi+0x2c]
 *  01228169   85c0             test eax,eax
 *  0122816b   74 19            je short .01228186
 *  0122816d   8b08             mov ecx,dword ptr ds:[eax]
 *  0122816f   ff41 04          inc dword ptr ds:[ecx+0x4]
 *  01228172   8b00             mov eax,dword ptr ds:[eax]
 *  01228174   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  01228177   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  0122817e   59               pop ecx
 *  0122817f   5f               pop edi
 *  01228180   5e               pop esi
 *  01228181   5b               pop ebx
 *  01228182   8be5             mov esp,ebp
 *  01228184   5d               pop ebp
 *  01228185   c3               retn
 *  01228186   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 *  01228189   85c9             test ecx,ecx
 *  0122818b   0f84 47010000    je .012282d8
 *  01228191   0fb743 14        movzx eax,word ptr ds:[ebx+0x14]
 *  01228195   50               push eax
 *  01228196   e8 950f0300      call .01259130
 *  0122819b   8bf0             mov esi,eax
 *  0122819d   8975 ec          mov dword ptr ss:[ebp-0x14],esi
 *  012281a0   85f6             test esi,esi
 *  012281a2   0f84 30010000    je .012282d8
 *  012281a8   6a 34            push 0x34
 *  012281aa   e8 297c1300      call .0135fdd8
 *  012281af   83c4 04          add esp,0x4
 *  012281b2   8bf8             mov edi,eax
 *  012281b4   897d e0          mov dword ptr ss:[ebp-0x20],edi
 *  012281b7   c745 fc 00000000 mov dword ptr ss:[ebp-0x4],0x0
 *  012281be   85ff             test edi,edi
 *  012281c0   74 1d            je short .012281df
 *  012281c2   c747 2c 41000000 mov dword ptr ds:[edi+0x2c],0x41
 *  012281c9   c647 32 00       mov byte ptr ds:[edi+0x32],0x0
 *  012281cd   c747 04 01000000 mov dword ptr ds:[edi+0x4],0x1
 *  012281d4   c707 00000000    mov dword ptr ds:[edi],0x0
 *  012281da   8945 e8          mov dword ptr ss:[ebp-0x18],eax
 *  012281dd   eb 05            jmp short .012281e4
 *  012281df   33ff             xor edi,edi
 *  012281e1   897d e8          mov dword ptr ss:[ebp-0x18],edi
 *  012281e4   c745 fc ffffffff mov dword ptr ss:[ebp-0x4],-0x1
 *  012281eb   0fb746 04        movzx eax,word ptr ds:[esi+0x4]
 *  012281ef   8947 1c          mov dword ptr ds:[edi+0x1c],eax
 *  012281f2   0fb746 06        movzx eax,word ptr ds:[esi+0x6]
 *  012281f6   8947 20          mov dword ptr ds:[edi+0x20],eax
 *  012281f9   0fbf46 0c        movsx eax,word ptr ds:[esi+0xc]
 *  012281fd   8947 10          mov dword ptr ds:[edi+0x10],eax
 *  01228200   0fbf46 0e        movsx eax,word ptr ds:[esi+0xe]
 *  01228204   8947 14          mov dword ptr ds:[edi+0x14],eax
 *  01228207   0fbf46 08        movsx eax,word ptr ds:[esi+0x8]
 *  0122820b   0345 0c          add eax,dword ptr ss:[ebp+0xc]
 *  0122820e   8947 08          mov dword ptr ds:[edi+0x8],eax
 *  01228211   0fbf46 0a        movsx eax,word ptr ds:[esi+0xa]
 *  01228215   8b4d 10          mov ecx,dword ptr ss:[ebp+0x10]
 *  01228218   2bc8             sub ecx,eax
 *  0122821a   894f 0c          mov dword ptr ds:[edi+0xc],ecx
 *  0122821d   0fb643 20        movzx eax,byte ptr ds:[ebx+0x20]
 *  01228221   8847 30          mov byte ptr ds:[edi+0x30],al
 *  01228224   c647 32 00       mov byte ptr ds:[edi+0x32],0x0
 *  01228228   0fb643 21        movzx eax,byte ptr ds:[ebx+0x21]
 *  0122822c   8847 31          mov byte ptr ds:[edi+0x31],al
 *  0122822f   8b43 1c          mov eax,dword ptr ds:[ebx+0x1c]
 *  01228232   8947 28          mov dword ptr ds:[edi+0x28],eax
 *  01228235   8b43 18          mov eax,dword ptr ds:[ebx+0x18]
 *  01228238   8947 24          mov dword ptr ds:[edi+0x24],eax
 *  0122823b   c745 fc 01000000 mov dword ptr ss:[ebp-0x4],0x1
 *  01228242   837f 1c 00       cmp dword ptr ds:[edi+0x1c],0x0
 *  01228246   74 64            je short .012282ac
 *  01228248   8b47 20          mov eax,dword ptr ds:[edi+0x20]
 *  0122824b   85c0             test eax,eax
 *  0122824d   74 5d            je short .012282ac
 *  0122824f   0fb776 04        movzx esi,word ptr ds:[esi+0x4]
 *  01228253   4e               dec esi
 *  01228254   83e6 fc          and esi,0xfffffffc
 *  01228257   83c6 04          add esi,0x4
 *  0122825a   8977 18          mov dword ptr ds:[edi+0x18],esi
 *  0122825d   0fafc6           imul eax,esi
 *  01228260   50               push eax
 *  01228261   8bcf             mov ecx,edi
 *  01228263   e8 a8f6ffff      call .01227910
 *  01228268   56               push esi
 *  01228269   ff37             push dword ptr ds:[edi]
 *  0122826b   ff75 ec          push dword ptr ss:[ebp-0x14]
 *  0122826e   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 *  01228271   e8 1a0f0300      call .01259190
 *  01228276   807b 21 00       cmp byte ptr ds:[ebx+0x21],0x0
 *  0122827a   74 0d            je short .01228289
 *  0122827c   ff77 28          push dword ptr ds:[edi+0x28]
 *  0122827f   ff77 24          push dword ptr ds:[edi+0x24]
 *  01228282   8bcf             mov ecx,edi
 *  01228284   e8 870affff      call .01218d10
 *  01228289   897d ec          mov dword ptr ss:[ebp-0x14],edi
 *  0122828c   ff47 04          inc dword ptr ds:[edi+0x4]
 *  0122828f   c645 fc 02       mov byte ptr ss:[ebp-0x4],0x2
 *  01228293   8d45 ec          lea eax,dword ptr ss:[ebp-0x14]
 *  01228296   50               push eax
 *  01228297   ff75 e4          push dword ptr ss:[ebp-0x1c]
 *  0122829a   53               push ebx
 *  0122829b   e8 50280000      call .0122aaf0
 *  012282a0   c645 fc 01       mov byte ptr ss:[ebp-0x4],0x1
 *  012282a4   8d4d ec          lea ecx,dword ptr ss:[ebp-0x14]
 *  012282a7   e8 84280000      call .0122ab30
 *  012282ac   c745 fc ffffffff mov dword ptr ss:[ebp-0x4],-0x1
 *  012282b3   8bc7             mov eax,edi
 *  012282b5   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  012282b8   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  012282bf   59               pop ecx
 *  012282c0   5f               pop edi
 *  012282c1   5e               pop esi
 *  012282c2   5b               pop ebx
 *  012282c3   8be5             mov esp,ebp
 *  012282c5   5d               pop ebp
 *  012282c6   c3               retn
 *  012282c7   8b4d e8          mov ecx,dword ptr ss:[ebp-0x18]
 *  012282ca   e8 71f6ffff      call .01227940
 *  012282cf   6a 00            push 0x0
 *  012282d1   6a 00            push 0x0
 *  012282d3   e8 83eb1300      call .01366e5b
 *  012282d8   a1 e89a4901      mov eax,dword ptr ds:[0x1499ae8]
 *  012282dd   8b0c85 f0d64b01  mov ecx,dword ptr ds:[eax*4+0x14bd6f0]
 *  012282e4   8b01             mov eax,dword ptr ds:[ecx]
 *  012282e6   ff75 10          push dword ptr ss:[ebp+0x10]
 *  012282e9   ff75 0c          push dword ptr ss:[ebp+0xc]
 *  012282ec   53               push ebx
 *  012282ed   ff50 1c          call dword ptr ds:[eax+0x1c]
 *  012282f0   8bf0             mov esi,eax
 *  012282f2   8975 e4          mov dword ptr ss:[ebp-0x1c],esi
 *  012282f5   ff46 04          inc dword ptr ds:[esi+0x4]
 *  012282f8   c745 fc 04000000 mov dword ptr ss:[ebp-0x4],0x4
 *  012282ff   8d45 e4          lea eax,dword ptr ss:[ebp-0x1c]
 *  01228302   50               push eax
 *  01228303   57               push edi
 *  01228304   53               push ebx
 *  01228305   e8 a62c0000      call .0122afb0
 *  0122830a   a1 a0a84b01      mov eax,dword ptr ds:[0x14ba8a0]
 *  0122830f   8b0d aca84b01    mov ecx,dword ptr ds:[0x14ba8ac]
 *  01228315   3bc1             cmp eax,ecx
 *  01228317   76 08            jbe short .01228321
 *  01228319   2bc1             sub eax,ecx
 *  0122831b   50               push eax
 *  0122831c   e8 1f2e0000      call .0122b140
 *  01228321   c745 fc ffffffff mov dword ptr ss:[ebp-0x4],-0x1
 *  01228328   8b46 04          mov eax,dword ptr ds:[esi+0x4]
 *  0122832b   83f8 01          cmp eax,0x1
 *  0122832e   75 2c            jnz short .0122835c
 *  01228330   8b06             mov eax,dword ptr ds:[esi]
 *  01228332   85c0             test eax,eax
 *  01228334   74 09            je short .0122833f
 *  01228336   50               push eax
 *  01228337   e8 3b7c1300      call .0135ff77
 *  0122833c   83c4 04          add esp,0x4
 *  0122833f   56               push esi
 *  01228340   e8 33781300      call .0135fb78
 *  01228345   83c4 04          add esp,0x4
 *  01228348   8bc6             mov eax,esi
 *  0122834a   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  0122834d   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  01228354   59               pop ecx
 *  01228355   5f               pop edi
 *  01228356   5e               pop esi
 *  01228357   5b               pop ebx
 *  01228358   8be5             mov esp,ebp
 *  0122835a   5d               pop ebp
 *  0122835b   c3               retn
 *  0122835c   48               dec eax
 *  0122835d   8946 04          mov dword ptr ds:[esi+0x4],eax
 *  01228360   8bc6             mov eax,esi
 *  01228362   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  01228365   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  0122836c   59               pop ecx
 *  0122836d   5f               pop edi
 *  0122836e   5e               pop esi
 *  0122836f   5b               pop ebx
 *  01228370   8be5             mov esp,ebp
 *  01228372   5d               pop ebp
 *  01228373   c3               retn
 *  01228374   cc               int3
 *  01228375   cc               int3
 *  01228376   cc               int3
 *  01228377   cc               int3
 *  01228378   cc               int3
 */

namespace { // unnamed

// Skip individual L'\n' which might cause repetition.
//bool NewLineWideCharSkipper(LPVOID data, DWORD *size, HookParam *)
//{
//  LPCWSTR text = (LPCWSTR)data;
//  if (*size == 2 && *text == L'\n')
//    return false;
//  return true;
//}
//

void NewKiriKiriZHook(DWORD addr)
{
  HookParam hp = {};
  hp.addr = addr;
  hp.off = pusha_ecx_off - 4;
  hp.split = hp.off;    // the same logic but diff value as KiriKiri1, use [ecx] as split
  hp.ind = 0x14;        // the same as KiriKiri1
  hp.length_offset = 1; // the same as KiriKiri1
  hp.type = USING_UNICODE|DATA_INDIRECT|USING_SPLIT|SPLIT_INDIRECT;
  //hp.filter_fun = NewLineWideCharFilter;
  ConsoleOutput("vnreng: INSERT KiriKiriZ");
  NewHook(hp, L"KiriKiriZ");

  ConsoleOutput("vnreng:KiriKiriZ: disable GDI hooks");
  DisableGDIHooks();
}

bool KiriKiriZHook1(DWORD esp_base, HookParam *)
{
  DWORD addr = retof(esp_base); // retaddr
  addr = MemDbg::findEnclosingAlignedFunction(addr, 0x400); // range is around 0x377c50 - 0x377a40 = 0x210
  if (!addr) {
    ConsoleOutput("vnreng:KiriKiriZ: failed to find enclosing function");
    return false; // stop looking
  }
  NewKiriKiriZHook(addr);
  ConsoleOutput("vnreng: KiriKiriZ1 inserted");
  return false; // stop looking
}

bool InsertKiriKiriZHook1()
{
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:KiriKiriZ1: failed to get memory range");
    return false;
  }

  ULONG addr = MemDbg::findCallerAddressAfterInt3((DWORD)::GetGlyphOutlineW, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:KiriKiriZ1: could not find caller of GetGlyphOutlineW");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.type = HOOK_EMPTY;
  hp.hook_fun = KiriKiriZHook1;
  ConsoleOutput("vnreng: INSERT KiriKiriZ1 empty hook");
  NewHook(hp, L"KiriKiriZ Hook");
  return true;
}

// jichi 1/30/2015: Add KiriKiriZ2 for サノバウィッチ
// It inserts to the same location as the old KiriKiriZ, but use a different way to find it.
bool InsertKiriKiriZHook2()
{
  const BYTE bytes[] = {
    0x38,0x4b, 0x21,     // 0122812f   384b 21          cmp byte ptr ds:[ebx+0x21],cl
    0x0f,0x95,0xc1,      // 01228132   0f95c1           setne cl
    0x33,0xc0,           // 01228135   33c0             xor eax,eax
    0x38,0x43, 0x20,     // 01228137   3843 20          cmp byte ptr ds:[ebx+0x20],al
    0x0f,0x95,0xc0,      // 0122813a   0f95c0           setne al
    0x33,0xc8,           // 0122813d   33c8             xor ecx,eax
    0x33,0x4b, 0x10,     // 0122813f   334b 10          xor ecx,dword ptr ds:[ebx+0x10]
    0x0f,0xb7,0x43, 0x14 // 01228142   0fb743 14        movzx eax,word ptr ds:[ebx+0x14]
  };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr);
  if (!addr) {
    ConsoleOutput("vnreng:KiriKiriZ2: pattern not found");
    return false;
  }

  // 012280e0   55               push ebp
  // 012280e1   8bec             mov ebp,esp
  addr = MemDbg::findEnclosingAlignedFunction(addr, 0x100); // 0x0122812f - 0x 012280dc = 83
  enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
  if (!addr || *(BYTE *)addr != push_ebp) {
    ConsoleOutput("vnreng:KiriKiriZ2: pattern found but the function offset is invalid");
    return false;
  }

  NewKiriKiriZHook(addr);
  ConsoleOutput("vnreng: KiriKiriZ2 inserted");
  return true;
}

} // unnamed namespace

// jichi 1/30/2015: Do KiriKiriZ2 first, which might insert to the same location as KiriKiri1.
bool InsertKiriKiriZHook()
{ return InsertKiriKiriZHook2() || InsertKiriKiriZHook1(); }

/********************************************************************************************
BGI hook:
  Usually game folder contains BGI.*. After first run BGI.gdb appears.

  BGI engine has font caching issue so the strategy is simple.
  First find call to TextOutA or TextOutW then reverse to function entry point,
  until full text is caught.
  After 2 tries we will get to the right place. Use ESP value to split text since
  it's likely to be different for different calls.
********************************************************************************************/
namespace { // unnamed
#if 0 // jichi 12/28/2013: dynamic BGI is not used
static bool FindBGIHook(DWORD fun, DWORD size, DWORD pt, WORD sig)
{
  if (!fun) {
    ConsoleOutput("vnreng:BGI: cannot find BGI hook");
    //swprintf(str, L"Can't find BGI hook: %.8X.",fun);
    //ConsoleOutput(str);
    return false;
  }
  //WCHAR str[0x40];
  //i=FindCallBoth(fun,size,pt);

  //swprintf(str, L"CALL addr: 0x%.8X",pt+i);
  //ConsoleOutput(str);
  for (DWORD i = fun, j = fun; j > i - 0x100; j--)
    if ((*(WORD *)(pt + j)) == sig) { // Fun entry 1.
      //swprintf(str, L"Entry 1: 0x%.8X",pt+j);
      //ConsoleOutput(str);
      for (DWORD k = i + 0x100; k < i+0x800; k++)
        if (*(BYTE *)(pt + k) == 0xe8)
          if (k + 5 + *(DWORD *)(pt + k + 1) == j) { // Find call to fun1.
            //swprintf(str, L"CALL to entry 1: 0x%.8X",pt+k);
            //ConsoleOutput(str);
            for (DWORD l = k; l > k - 0x100;l--)
              if ((*(WORD *)(pt + l)) == 0xec83) { // Fun entry 2.
                //swprintf(str, L"Entry 2(final): 0x%.8X",pt+l);
                //ConsoleOutput(str);
                HookParam hp = {};
                hp.addr = (DWORD)pt + l;
                hp.off = 0x8;
                hp.split = -0x18;
                hp.length_offset = 1;
                hp.type = BIG_ENDIAN|USING_SPLIT;
                ConsoleOutput("vnreng:INSERT DynamicBGI");
                NewHook(hp, L"BGI");
                return true;
              }
          }
    }
  ConsoleOutput("vnreng:DynamicBGI: failed");
  return false;
}
bool InsertBGIDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != TextOutA && addr != TextOutW)  {
    //ConsoleOutput("vnreng:DynamicBGI: failed");
    return false;
  }

  DWORD i = *(DWORD *)(stack + 4) - module_base_;
  return FindBGIHook(i, module_limit_ - module_base_, module_base_, 0xec83);
}
#endif // 0

/** jichi 5/12/2014
 *  Sample game:  FORTUNE ARTERIAL, case 2 at 0x41ebd0
 *
 *  sub_41EBD0 proc near, seems to take 5 parameters
 *
 *  0041ebd0  /$ 83ec 28        sub esp,0x28 ; jichi: hook here, beginning of the function
 *  0041ebd3  |. 55             push ebp
 *  0041ebd4  |. 8b6c24 38      mov ebp,dword ptr ss:[esp+0x38]
 *  0041ebd8  |. 81fd 00ff0000  cmp ebp,0xff00
 *  0041ebde  |. 0f82 e1000000  jb bgi.0041ecc5
 *  0041ebe4  |. 81fd ffff0000  cmp ebp,0xffff
 *  0041ebea  |. 0f87 d5000000  ja bgi.0041ecc5
 *  0041ebf0  |. a1 54634900    mov eax,dword ptr ds:[0x496354]
 *  0041ebf5  |. 8bd5           mov edx,ebp
 *  0041ebf7  |. 81e2 ff000000  and edx,0xff
 *  0041ebfd  |. 53             push ebx
 *  0041ebfe  |. 4a             dec edx
 *  0041ebff  |. 33db           xor ebx,ebx
 *  0041ec01  |. 3bd0           cmp edx,eax
 *  0041ec03  |. 56             push esi
 *  0041ec04  |. 0f8d 8a000000  jge bgi.0041ec94
 *  0041ec0a  |. 57             push edi
 *  0041ec0b  |. b9 06000000    mov ecx,0x6
 *  0041ec10  |. be 5c634900    mov esi,bgi.0049635c
 *  0041ec15  |. 8d7c24 20      lea edi,dword ptr ss:[esp+0x20]
 *  0041ec19  |. f3:a5          rep movs dword ptr es:[edi],dword ptr ds>
 *  0041ec1b  |. 8b0d 58634900  mov ecx,dword ptr ds:[0x496358]
 *  0041ec21  |. 8b7424 3c      mov esi,dword ptr ss:[esp+0x3c]
 *  0041ec25  |. 8bc1           mov eax,ecx
 *  0041ec27  |. 5f             pop edi
 *  0041ec28  |. 0fafc2         imul eax,edx
 *  0041ec2b  |. 8b56 08        mov edx,dword ptr ds:[esi+0x8]
 *  0041ec2e  |. 894424 0c      mov dword ptr ss:[esp+0xc],eax
 *  0041ec32  |. 3bca           cmp ecx,edx
 *  0041ec34  |. 7e 02          jle short bgi.0041ec38
 *  0041ec36  |. 8bca           mov ecx,edx
 *  0041ec38  |> 8d4401 ff      lea eax,dword ptr ds:[ecx+eax-0x1]
 *  0041ec3c  |. 8b4c24 28      mov ecx,dword ptr ss:[esp+0x28]
 *  0041ec40  |. 894424 14      mov dword ptr ss:[esp+0x14],eax
 *  0041ec44  |. 8b46 0c        mov eax,dword ptr ds:[esi+0xc]
 *  0041ec47  |. 3bc8           cmp ecx,eax
 *  0041ec49  |. 895c24 10      mov dword ptr ss:[esp+0x10],ebx
 *  0041ec4d  |. 77 02          ja short bgi.0041ec51
 *  0041ec4f  |. 8bc1           mov eax,ecx
 *  0041ec51  |> 8d4c24 0c      lea ecx,dword ptr ss:[esp+0xc]
 *  0041ec55  |. 8d5424 1c      lea edx,dword ptr ss:[esp+0x1c]
 *  0041ec59  |. 48             dec eax
 *  0041ec5a  |. 51             push ecx
 *  0041ec5b  |. 52             push edx
 *  0041ec5c  |. 894424 20      mov dword ptr ss:[esp+0x20],eax
 *  0041ec60  |. e8 7b62feff    call bgi.00404ee0
 *  0041ec65  |. 8b4424 34      mov eax,dword ptr ss:[esp+0x34]
 *  0041ec69  |. 83c4 08        add esp,0x8
 *  0041ec6c  |. 83f8 03        cmp eax,0x3
 *  0041ec6f  |. 75 15          jnz short bgi.0041ec86
 *  0041ec71  |. 8b4424 48      mov eax,dword ptr ss:[esp+0x48]
 *  0041ec75  |. 8d4c24 1c      lea ecx,dword ptr ss:[esp+0x1c]
 *  0041ec79  |. 50             push eax
 *  0041ec7a  |. 51             push ecx
 *  0041ec7b  |. 56             push esi
 *  0041ec7c  |. e8 1fa0feff    call bgi.00408ca0
 */
bool InsertBGI1Hook()
{
  union {
    DWORD i;
    DWORD *id;
    BYTE *ib;
  };
  HookParam hp = {};
  for (i = module_base_ + 0x1000; i < module_limit_; i++) {
    if (ib[0] == 0x3d) {
      i++;
      if (id[0] == 0xffff) { //cmp eax,0xffff
        hp.addr = SafeFindEntryAligned(i, 0x40);
        if (hp.addr) {
          hp.off = 0xc;
          hp.split = -0x18;
          hp.type = BIG_ENDIAN|USING_SPLIT;
          hp.length_offset = 1;
          ConsoleOutput("vnreng:INSERT BGI#1");
          NewHook(hp, L"BGI");
          //RegisterEngineType(ENGINE_BGI);
          return true;
        }
      }
    }
    if (ib[0] == 0x81 && ((ib[1] & 0xf8) == 0xf8)) {
      i += 2;
      if (id[0] == 0xffff) { //cmp reg,0xffff
        hp.addr = SafeFindEntryAligned(i, 0x40);
        if (hp.addr) {
          hp.off = 0xc;
          hp.split = -0x18;
          hp.type = BIG_ENDIAN|USING_SPLIT;
          hp.length_offset = 1;
          ConsoleOutput("vnreng: INSERT BGI#2");
          NewHook(hp, L"BGI");
          //RegisterEngineType(ENGINE_BGI);
          return true;
        }
      }
    }
  }
  //ConsoleOutput("Unknown BGI engine.");

  //ConsoleOutput("Probably BGI. Wait for text.");
  //SwitchTrigger(true);
  //trigger_fun_=InsertBGIDynamicHook;
  ConsoleOutput("vnreng:BGI: failed");
  return false;
}

/**
 *  jichi 2/5/2014: Add an alternative BGI hook
 *
 *  Issue: This hook cannot extract character name for コトバの消えた日
 *
 *  See: http://tieba.baidu.com/p/2845113296
 *  世界と世界の真ん中で
 *  - /HSN4@349E0:sekachu.exe // Disabled BGI3, floating split char
 *  - /HS-1C:-4@68E56 // Not used, cannot detect character name
 *  - /HSC@34C80:sekachu.exe  // BGI2, extract both scenario and character names
 *
 *  [Lump of Sugar] 世界と世界の真ん中で
 *  /HSC@34C80:sekachu.exe
 *  - addr: 216192 = 0x34c80
 *  - module: 3599131534
 *  - off: 12 = 0xc
 *  - type: 65 = 0x41
 *
 *  base: 0x11a0000
 *  hook_addr = base + addr = 0x11d4c80
 *
 *  011d4c7e     cc             int3
 *  011d4c7f     cc             int3
 *  011d4c80  /$ 55             push ebp    ; jichi: hook here
 *  011d4c81  |. 8bec           mov ebp,esp
 *  011d4c83  |. 6a ff          push -0x1
 *  011d4c85  |. 68 e6592601    push sekachu.012659e6
 *  011d4c8a  |. 64:a1 00000000 mov eax,dword ptr fs:[0]
 *  011d4c90  |. 50             push eax
 *  011d4c91  |. 81ec 300d0000  sub esp,0xd30
 *  011d4c97  |. a1 d8c82801    mov eax,dword ptr ds:[0x128c8d8]
 *  011d4c9c  |. 33c5           xor eax,ebp
 *  011d4c9e  |. 8945 f0        mov dword ptr ss:[ebp-0x10],eax
 *  011d4ca1  |. 53             push ebx
 *  011d4ca2  |. 56             push esi
 *  011d4ca3  |. 57             push edi
 *  011d4ca4  |. 50             push eax
 *  011d4ca5  |. 8d45 f4        lea eax,dword ptr ss:[ebp-0xc]
 *  011d4ca8  |. 64:a3 00000000 mov dword ptr fs:[0],eax
 *  011d4cae  |. 8b4d 0c        mov ecx,dword ptr ss:[ebp+0xc]
 *  011d4cb1  |. 8b55 18        mov edx,dword ptr ss:[ebp+0x18]
 *  011d4cb4  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  011d4cb7  |. 8b5d 10        mov ebx,dword ptr ss:[ebp+0x10]
 *  011d4cba  |. 8b7d 38        mov edi,dword ptr ss:[ebp+0x38]
 *  011d4cbd  |. 898d d8f3ffff  mov dword ptr ss:[ebp-0xc28],ecx
 *  011d4cc3  |. 8b4d 28        mov ecx,dword ptr ss:[ebp+0x28]
 *  011d4cc6  |. 8995 9cf3ffff  mov dword ptr ss:[ebp-0xc64],edx
 *  011d4ccc  |. 51             push ecx
 *  011d4ccd  |. 8b0d 305c2901  mov ecx,dword ptr ds:[0x1295c30]
 *  011d4cd3  |. 8985 e0f3ffff  mov dword ptr ss:[ebp-0xc20],eax
 *  011d4cd9  |. 8b45 1c        mov eax,dword ptr ss:[ebp+0x1c]
 *  011d4cdc  |. 8d95 4cf4ffff  lea edx,dword ptr ss:[ebp-0xbb4]
 *  011d4ce2  |. 52             push edx
 *  011d4ce3  |. 899d 40f4ffff  mov dword ptr ss:[ebp-0xbc0],ebx
 *  011d4ce9  |. 8985 1cf4ffff  mov dword ptr ss:[ebp-0xbe4],eax
 *  011d4cef  |. 89bd f0f3ffff  mov dword ptr ss:[ebp-0xc10],edi
 *  011d4cf5  |. e8 862efdff    call sekachu.011a7b80
 *  011d4cfa  |. 33c9           xor ecx,ecx
 *  011d4cfc  |. 8985 60f3ffff  mov dword ptr ss:[ebp-0xca0],eax
 *  011d4d02  |. 3bc1           cmp eax,ecx
 *  011d4d04  |. 0f84 0f1c0000  je sekachu.011d6919
 *  011d4d0a  |. e8 31f6ffff    call sekachu.011d4340
 *  011d4d0f  |. e8 6cf8ffff    call sekachu.011d4580
 *  011d4d14  |. 8985 64f3ffff  mov dword ptr ss:[ebp-0xc9c],eax
 *  011d4d1a  |. 8a03           mov al,byte ptr ds:[ebx]
 *  011d4d1c  |. 898d 90f3ffff  mov dword ptr ss:[ebp-0xc70],ecx
 *  011d4d22  |. 898d 14f4ffff  mov dword ptr ss:[ebp-0xbec],ecx
 *  011d4d28  |. 898d 38f4ffff  mov dword ptr ss:[ebp-0xbc8],ecx
 *  011d4d2e  |. 8d71 01        lea esi,dword ptr ds:[ecx+0x1]
 *  011d4d31  |. 3c 20          cmp al,0x20                 ; jichi: pattern starts
 *  011d4d33  |. 7d 75          jge short sekachu.011d4daa
 *  011d4d35  |. 0fbec0         movsx eax,al
 *  011d4d38  |. 83c0 fe        add eax,-0x2                             ;  switch (cases 2..8)
 *  011d4d3b  |. 83f8 06        cmp eax,0x6
 *  011d4d3e  |. 77 6a          ja short sekachu.011d4daa
 *  011d4d40  |. ff2485 38691d0>jmp dword ptr ds:[eax*4+0x11d6938]
 *
 *  蒼の彼方 体験版 (8/6/2014)
 *  01312cce     cc             int3    ; jichi: reladdr = 0x32cd0
 *  01312ccf     cc             int3
 *  01312cd0   $ 55             push ebp
 *  01312cd1   . 8bec           mov ebp,esp
 *  01312cd3   . 83e4 f8        and esp,0xfffffff8
 *  01312cd6   . 6a ff          push -0x1
 *  01312cd8   . 68 86583a01    push 蒼の彼方.013a5886
 *  01312cdd   . 64:a1 00000000 mov eax,dword ptr fs:[0]
 *  01312ce3   . 50             push eax
 *  01312ce4   . 81ec 38090000  sub esp,0x938
 *  01312cea   . a1 24673c01    mov eax,dword ptr ds:[0x13c6724]
 *  01312cef   . 33c4           xor eax,esp
 *  01312cf1   . 898424 3009000>mov dword ptr ss:[esp+0x930],eax
 *  01312cf8   . 53             push ebx
 *  01312cf9   . 56             push esi
 *  01312cfa   . 57             push edi
 *  01312cfb   . a1 24673c01    mov eax,dword ptr ds:[0x13c6724]
 *  01312d00   . 33c4           xor eax,esp
 *  01312d02   . 50             push eax
 *  01312d03   . 8d8424 4809000>lea eax,dword ptr ss:[esp+0x948]
 *  01312d0a   . 64:a3 00000000 mov dword ptr fs:[0],eax
 *  01312d10   . 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  01312d13   . 8b7d 0c        mov edi,dword ptr ss:[ebp+0xc]
 *  01312d16   . 8b5d 30        mov ebx,dword ptr ss:[ebp+0x30]
 *  01312d19   . 898424 8800000>mov dword ptr ss:[esp+0x88],eax
 *  01312d20   . 8b45 14        mov eax,dword ptr ss:[ebp+0x14]
 *  01312d23   . 898c24 8c00000>mov dword ptr ss:[esp+0x8c],ecx
 *  01312d2a   . 8b0d a8734a01  mov ecx,dword ptr ds:[0x14a73a8]
 *  01312d30   . 894424 4c      mov dword ptr ss:[esp+0x4c],eax
 *  01312d34   . 899424 bc00000>mov dword ptr ss:[esp+0xbc],edx
 *  01312d3b   . 8b55 20        mov edx,dword ptr ss:[ebp+0x20]
 *  01312d3e   . 51             push ecx                                 ; /arg1 => 00000000
 *  01312d3f   . 8d8424 0c02000>lea eax,dword ptr ss:[esp+0x20c]         ; |
 *  01312d46   . 897c24 34      mov dword ptr ss:[esp+0x34],edi          ; |
 *  01312d4a   . 899c24 8800000>mov dword ptr ss:[esp+0x88],ebx          ; |
 *  01312d51   . e8 ca59fdff    call 蒼の彼方.012e8720                       ; \蒼の彼方.012e8720
 *  01312d56   . 33c9           xor ecx,ecx
 *  01312d58   . 898424 f400000>mov dword ptr ss:[esp+0xf4],eax
 *  01312d5f   . 3bc1           cmp eax,ecx
 *  01312d61   . 0f84 391b0000  je 蒼の彼方.013148a0
 *  01312d67   . e8 54280000    call 蒼の彼方.013155c0
 *  01312d6c   . e8 7f2a0000    call 蒼の彼方.013157f0
 *  01312d71   . 898424 f800000>mov dword ptr ss:[esp+0xf8],eax
 *  01312d78   . 8a07           mov al,byte ptr ds:[edi]
 *  01312d7a   . 898c24 c400000>mov dword ptr ss:[esp+0xc4],ecx
 *  01312d81   . 894c24 2c      mov dword ptr ss:[esp+0x2c],ecx
 *  01312d85   . 894c24 1c      mov dword ptr ss:[esp+0x1c],ecx
 *  01312d89   . b9 01000000    mov ecx,0x1
 *  01312d8e   . 3c 20          cmp al,0x20     ; jichi: pattern starts
 *  01312d90   . 7d 58          jge short 蒼の彼方.01312dea
 *  01312d92   . 0fbec0         movsx eax,al
 *  01312d95   . 83c0 fe        add eax,-0x2                             ;  switch (cases 2..8)
 *  01312d98   . 83f8 06        cmp eax,0x6
 *  01312d9b   . 77 4d          ja short 蒼の彼方.01312dea
 *  01312d9d   . ff2485 c448310>jmp dword ptr ds:[eax*4+0x13148c4]
 *  01312da4   > 898c24 c400000>mov dword ptr ss:[esp+0xc4],ecx          ;  case 2 of switch 01312d95
 *  01312dab   . 03f9           add edi,ecx
 *  01312dad   . eb 37          jmp short 蒼の彼方.01312de6
 *  01312daf   > 894c24 2c      mov dword ptr ss:[esp+0x2c],ecx          ;  case 3 of switch 01312d95
 *  01312db3   . 03f9           add edi,ecx
 *  01312db5   . eb 2f          jmp short 蒼の彼方.01312de6
 *  01312db7   > ba e0103b01    mov edx,蒼の彼方.013b10e0                    ;  case 4 of switch 01312d95
 *  01312dbc   . eb 1a          jmp short 蒼の彼方.01312dd8
 *  01312dbe   > ba e4103b01    mov edx,蒼の彼方.013b10e4                    ;  case 5 of switch 01312d95
 *  01312dc3   . eb 13          jmp short 蒼の彼方.01312dd8
 *  01312dc5   > ba e8103b01    mov edx,蒼の彼方.013b10e8                    ;  case 6 of switch 01312d95
 *  01312dca   . eb 0c          jmp short 蒼の彼方.01312dd8
 *  01312dcc   > ba ec103b01    mov edx,蒼の彼方.013b10ec                    ;  case 7 of switch 01312d95
 *  01312dd1   . eb 05          jmp short 蒼の彼方.01312dd8
 *  01312dd3   > ba f0103b01    mov edx,蒼の彼方.013b10f0                    ;  case 8 of switch 01312d95
 *  01312dd8   > 8d7424 14      lea esi,dword ptr ss:[esp+0x14]
 *  01312ddc   . 894c24 1c      mov dword ptr ss:[esp+0x1c],ecx
 *  01312de0   . e8 1b8dffff    call 蒼の彼方.0130bb00
 *  01312de5   . 47             inc edi
 *  01312de6   > 897c24 30      mov dword ptr ss:[esp+0x30],edi
 *  01312dea   > 8d8424 0802000>lea eax,dword ptr ss:[esp+0x208]         ;  default case of switch 01312d95
 *  01312df1   . e8 ba1b0000    call 蒼の彼方.013149b0
 *  01312df6   . 837d 10 00     cmp dword ptr ss:[ebp+0x10],0x0
 *  01312dfa   . 8bb424 2802000>mov esi,dword ptr ss:[esp+0x228]
 *  01312e01   . 894424 5c      mov dword ptr ss:[esp+0x5c],eax
 *  01312e05   . 74 12          je short 蒼の彼方.01312e19
 *  01312e07   . 56             push esi                                 ; /arg1
 *  01312e08   . e8 c31b0000    call 蒼の彼方.013149d0                       ; \蒼の彼方.013149d0
 *  01312e0d   . 83c4 04        add esp,0x4
 *  01312e10   . 898424 c000000>mov dword ptr ss:[esp+0xc0],eax
 *  01312e17   . eb 0b          jmp short 蒼の彼方.01312e24
 *  01312e19   > c78424 c000000>mov dword ptr ss:[esp+0xc0],0x0
 *  01312e24   > 8b4b 04        mov ecx,dword ptr ds:[ebx+0x4]
 *  01312e27   . 0fafce         imul ecx,esi
 *  01312e2a   . b8 1f85eb51    mov eax,0x51eb851f
 *  01312e2f   . f7e9           imul ecx
 *  01312e31   . c1fa 05        sar edx,0x5
 *  01312e34   . 8bca           mov ecx,edx
 *  01312e36   . c1e9 1f        shr ecx,0x1f
 *  01312e39   . 03ca           add ecx,edx
 *  01312e3b   . 894c24 70      mov dword ptr ss:[esp+0x70],ecx
 *  01312e3f   . 85c9           test ecx,ecx
 *  01312e41   . 7f 09          jg short 蒼の彼方.01312e4c
 *  01312e43   . b9 01000000    mov ecx,0x1
 *  01312e48   . 894c24 70      mov dword ptr ss:[esp+0x70],ecx
 *  01312e4c   > 8b53 08        mov edx,dword ptr ds:[ebx+0x8]
 *  01312e4f   . 0fafd6         imul edx,esi
 *  01312e52   . b8 1f85eb51    mov eax,0x51eb851f
 *  01312e57   . f7ea           imul edx
 *  01312e59   . c1fa 05        sar edx,0x5
 *  01312e5c   . 8bc2           mov eax,edx
 *  01312e5e   . c1e8 1f        shr eax,0x1f
 *  01312e61   . 03c2           add eax,edx
 *  01312e63   . 894424 78      mov dword ptr ss:[esp+0x78],eax
 *  01312e67   . 85c0           test eax,eax
 *  01312e69   . 7f 09          jg short 蒼の彼方.01312e74
 *  01312e6b   . b8 01000000    mov eax,0x1
 *  01312e70   . 894424 78      mov dword ptr ss:[esp+0x78],eax
 *  01312e74   > 33d2           xor edx,edx
 *  01312e76   . 895424 64      mov dword ptr ss:[esp+0x64],edx
 *  01312e7a   . 895424 6c      mov dword ptr ss:[esp+0x6c],edx
 *  01312e7e   . 8b13           mov edx,dword ptr ds:[ebx]
 *  01312e80   . 4a             dec edx                                  ;  switch (cases 1..2)
 *  01312e81   . 74 0e          je short 蒼の彼方.01312e91
 *  01312e83   . 4a             dec edx
 *  01312e84   . 75 13          jnz short 蒼の彼方.01312e99
 *  01312e86   . 8d1409         lea edx,dword ptr ds:[ecx+ecx]           ;  case 2 of switch 01312e80
 *  01312e89   . 895424 64      mov dword ptr ss:[esp+0x64],edx
 *  01312e8d   . 03c0           add eax,eax
 *  01312e8f   . eb 04          jmp short 蒼の彼方.01312e95
 *  01312e91   > 894c24 64      mov dword ptr ss:[esp+0x64],ecx          ;  case 1 of switch 01312e80
 *  01312e95   > 894424 6c      mov dword ptr ss:[esp+0x6c],eax
 *  01312e99   > 8b9c24 3802000>mov ebx,dword ptr ss:[esp+0x238]         ;  default case of switch 01312e80
 *  01312ea0   . 8bc3           mov eax,ebx
 *  01312ea2   . e8 d98bffff    call 蒼の彼方.0130ba80
 *  01312ea7   . 8bc8           mov ecx,eax
 *  01312ea9   . 8bc3           mov eax,ebx
 *  01312eab   . e8 e08bffff    call 蒼の彼方.0130ba90
 *  01312eb0   . 6a 01          push 0x1                                 ; /arg1 = 00000001
 *  01312eb2   . 8bd0           mov edx,eax                              ; |
 *  01312eb4   . 8db424 1c01000>lea esi,dword ptr ss:[esp+0x11c]         ; |
 *  01312ebb   . e8 3056fdff    call 蒼の彼方.012e84f0                       ; \蒼の彼方.012e84f0
 *  01312ec0   . 8bc7           mov eax,edi
 *  01312ec2   . 83c4 04        add esp,0x4
 *  01312ec5   . 8d70 01        lea esi,dword ptr ds:[eax+0x1]
 *  01312ec8   > 8a08           mov cl,byte ptr ds:[eax]
 *  01312eca   . 40             inc eax
 *  01312ecb   . 84c9           test cl,cl
 *  01312ecd   .^75 f9          jnz short 蒼の彼方.01312ec8
 *  01312ecf   . 2bc6           sub eax,esi
 *  01312ed1   . 40             inc eax
 *  01312ed2   . 50             push eax
 *  01312ed3   . e8 e74c0600    call 蒼の彼方.01377bbf
 *  01312ed8   . 33f6           xor esi,esi
 *  01312eda   . 83c4 04        add esp,0x4
 */
//static inline size_t _bgistrlen(LPCSTR text)
//{
//  size_t r = ::strlen(text);
//  if (r >=2 && *(WORD *)(text + r - 2) == 0xa581) // remove trailing ▼ = \x81\xa5
//    r -= 2;
//  return r;
//}
//
//static void SpecialHookBGI2(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
//{
//  LPCSTR text = (LPCSTR)*(DWORD *)(esp_base + hp->off);
//  if (text) {
//    *data = (DWORD)text;
//    *len = _bgistrlen(text);
//  }
//}

bool InsertBGI2Hook()
{
  const BYTE bytes[] = {
    0x3c, 0x20,      // 011d4d31  |. 3c 20          cmp al,0x20
    0x7d, XX,        // 011d4d33  |. 7d 75          jge short sekachu.011d4daa ; jichi: 0x75 or 0x58
    0x0f,0xbe,0xc0,  // 011d4d35  |. 0fbec0         movsx eax,al
    0x83,0xc0, 0xfe, // 011d4d38  |. 83c0 fe        add eax,-0x2               ;  switch (cases 2..8)
    0x83,0xf8, 0x06  // 011d4d3b  |. 83f8 06        cmp eax,0x6
    // The following code does not exist in newer BGI games after 蒼の彼方
    //0x77, 0x6a     // 011d4d3e  |. 77 6a          ja short sekachu.011d4daa
  };
  enum {  // distance to the beginning of the function
    hook_offset_3 = 0x34c80 - 0x34d31 // for old BGI2 game, text is in arg2
    , hook_offset_2 = 0x01312cd0 - 0x01312d8e // for new BGI2 game since 蒼の彼方 (2014/08), text is in arg3
  };

  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::matchBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(reladdr);
  if (!addr) {
    ConsoleOutput("vnreng:BGI2: pattern not found");
    return false;
  }

  DWORD funaddr = MemDbg::findEnclosingAlignedFunction(addr, 0x100); // range is around 177 ~ 190

  enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
  if (!funaddr || *(BYTE *)funaddr != push_ebp) {
    ConsoleOutput("vnreng:BGI2: pattern found but the function offset is invalid");
    return false;
  }

  HookParam hp = {};
  switch (funaddr - addr) {
  case hook_offset_3: hp.off = 4 * 3; break; // arg3
  case hook_offset_2: hp.off = 4 * 2; break; // arg2
  default:
    ConsoleOutput("vnreng:BGI2: function found bug unrecognized hook offset");
    return false;
  }
  hp.addr = funaddr;

  // jichi 5/12/2014: Using split could distinguish name and choices. But the signature might become unstable
  hp.type = USING_STRING|USING_SPLIT;
  hp.split = 4 * 8; // pseudo arg8
  //hp.split = -0x18;

  //ITH_GROWL_DWORD2(hp.addr, module_base_);

  ConsoleOutput("vnreng: INSERT BGI2");
  NewHook(hp, L"BGI2");

  // Disable TextOutA, which is cached and hence missing characters.
  ConsoleOutput("vnreng:BGI2: disable GDI hooks");
  DisableGDIHooks();
  return true;
}

#if 0
/**
 *  jichi 1/31/2014: Add a new BGI hook
 *  See: http://www.hongfire.com/forum/showthread.php/36807-AGTH-text-extraction-tool-for-games-translation/page702
 *  See: http://www.hongfire.com/forum/showthread.php/36807-AGTH-text-extraction-tool-for-games-translation/page716
 *
 *  Issue: This hook has floating split char
 *
 *  [ぷちけろ] コトバの消えた日 ～心まで裸にする純愛調教～体験版
 *  /HS-1C:-4@68E56:BGI.exe
 *  - addr: 429654 (0x68e56)
 *  - module: 3927275266 (0xea157702)
 *  - off: 4294967264 = 0xffffffe0 = -0x20
 *  - split: 4294967288 = 0xfffffff8 = -0x8
 *  - type: 81 = 0x51
 *
 *  00e88e3d     cc             int3
 *  00e88e3e     cc             int3
 *  00e88e3f     cc             int3
 *  00e88e40  /. 55             push ebp
 *  00e88e41  |. 8bec           mov ebp,esp
 *  00e88e43  |. 56             push esi
 *  00e88e44  |. 57             push edi
 *  00e88e45  |. 8b7d 08        mov edi,dword ptr ss:[ebp+0x8]
 *  00e88e48  |. 57             push edi
 *  00e88e49  |. e8 c28a0100    call bgi.00ea1910
 *  00e88e4e  |. 57             push edi                                 ; |arg1
 *  00e88e4f  |. 8bf0           mov esi,eax                              ; |
 *  00e88e51  |. e8 ba8a0100    call bgi.00ea1910                        ; \bgi.00ea1910
 *  00e88e56  |. 83c4 08        add esp,0x8 ; jichi: hook here
 *  00e88e59  |. 2bc6           sub eax,esi
 *  00e88e5b  |. eb 03          jmp short bgi.00e88e60
 *  00e88e5d  |  8d49 00        lea ecx,dword ptr ds:[ecx]
 *  00e88e60  |> 8a0e           /mov cl,byte ptr ds:[esi]
 *  00e88e62  |. 880c30         |mov byte ptr ds:[eax+esi],cl
 *  00e88e65  |. 46             |inc esi
 *  00e88e66  |. 84c9           |test cl,cl
 *  00e88e68  |.^75 f6          \jnz short bgi.00e88e60
 *  00e88e6a  |. 5f             pop edi
 *  00e88e6b  |. 33c0           xor eax,eax
 *  00e88e6d  |. 5e             pop esi
 *  00e88e6e  |. 5d             pop ebp
 *  00e88e6f  \. c3             retn
 */
bool InsertBGI3Hook()
{
  const BYTE bytes[] = {
    0x83,0xc4, 0x08,// 00e88e56  |. 83c4 08        add esp,0x8 ; hook here
    0x2b,0xc6,      // 00e88e59  |. 2bc6           sub eax,esi
    0xeb, 0x03,     // 00e88e5b  |. eb 03          jmp short bgi.00e88e60
    0x8d,0x49, 0x00,// 00e88e5d  |  8d49 00        lea ecx,dword ptr ds:[ecx]
    0x8a,0x0e,      // 00e88e60  |> 8a0e           /mov cl,byte ptr ds:[esi]
    0x88,0x0c,0x30, // 00e88e62  |. 880c30         |mov byte ptr ds:[eax+esi],cl
    0x46,           // 00e88e65  |. 46             |inc esi
    0x84,0xc9,      // 00e88e66  |. 84c9           |test cl,cl
    0x75, 0xf6      // 00e88e68  |.^75 f6          \jnz short bgi.00e88e60
    //0x5f,           // 00e88e6a  |. 5f             pop edi
    //0x33,0xc0,      // 00e88e6b  |. 33c0           xor eax,eax
    //0x5e,           // 00e88e6d  |. 5e             pop esi
    //0x5d,           // 00e88e6e  |. 5d             pop ebp
    //0xc3            // 00e88e6f  \. c3             retn
  };
  //enum { hook_offset = 0 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //reladdr = 0x68e56;
  if (!addr) {
    ConsoleOutput("vnreng:BGI3: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.type = USING_STRING|USING_SPLIT;
  hp.off = -0x20;
  hp.split = -0x8;
  hp.addr = addr;

  //ITH_GROWL_DWORD2(hp.addr, module_base_);

  ConsoleOutput("vnreng: INSERT BGI3");
  NewHook(hp, L"BGI3");
  return true;
}
#endif // 0
} // unnamed

// jichi 5/12/2014: BGI1 and BGI2 game can co-exist, such as 世界と世界の真ん中で
// BGI1 can exist in both old and new games
// BGI2 only exist in new games
// Insert BGI2 first.
bool InsertBGIHook()
{ return InsertBGI2Hook() ||  InsertBGI1Hook(); }

/********************************************************************************************
Reallive hook:
  Process name is reallive.exe or reallive*.exe.

  Technique to find Reallive hook is quite different from 2 above.
  Usually Reallive engine has a font caching issue. This time we wait
  until the first call to GetGlyphOutlineA. Reallive engine usually set
  up stack frames so we can just refer to EBP to find function entry.

********************************************************************************************/
static bool InsertRealliveDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != ::GetGlyphOutlineA)
    return false;
  if (DWORD i = frame) {
    i = *(DWORD *)(i + 4);
    for (DWORD j = i; j > i - 0x100; j--)
      if (*(WORD *)j == 0xec83) { // jichi 7/26/2014: function starts
        HookParam hp = {};
        hp.addr = j;
        hp.off = 0x14;
        hp.split = -0x18;
        hp.length_offset = 1;
        hp.type = BIG_ENDIAN|USING_SPLIT;
        NewHook(hp, L"RealLive");
        //RegisterEngineType(ENGINE_REALLIVE);
        return true;
      }
  }
  return true; // jichi 12/25/2013: return true
}
void InsertRealliveHook()
{
  //ConsoleOutput("Probably Reallive. Wait for text.");
  ConsoleOutput("vnreng: TRIGGER Reallive");
  trigger_fun_ = InsertRealliveDynamicHook;
  SwitchTrigger(true);
}

namespace { // unnamed

/**
 *  jichi 8/17/2013:  SiglusEngine from siglusengine.exe
 *  The old hook does not work for new games.
 *  The new hook cannot recognize character names.
 *  Insert old first. As the pattern could also be found in the old engine.
 */

/** jichi 10/25/2014: new SiglusEngine2 that can extract character name
 *
 *  Sample game: リア充クラスメイト孕ませ催眠 -- /HW-4@F67DC:SiglusEngine.exe
 *  The character is in [edx+ecx*2]. Text in edx, and offset in ecx.
 *
 *  002667be   cc               int3
 *  002667bf   cc               int3
 *  002667c0   55               push ebp ; jichi: hook here
 *  002667c1   8bec             mov ebp,esp
 *  002667c3   8bd1             mov edx,ecx
 *  002667c5   8b4d 0c          mov ecx,dword ptr ss:[ebp+0xc]
 *  002667c8   83f9 01          cmp ecx,0x1
 *  002667cb   75 17            jnz short .002667e4
 *  002667cd   837a 14 08       cmp dword ptr ds:[edx+0x14],0x8
 *  002667d1   72 02            jb short .002667d5
 *  002667d3   8b12             mov edx,dword ptr ds:[edx]
 *  002667d5   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 *  002667d8   66:8b45 10       mov ax,word ptr ss:[ebp+0x10]
 *  002667dc   66:89044a        mov word ptr ds:[edx+ecx*2],ax  ; jichi: wchar_t is in ax
 *  002667e0   5d               pop ebp
 *  002667e1   c2 0c00          retn 0xc
 *  002667e4   837a 14 08       cmp dword ptr ds:[edx+0x14],0x8
 *  002667e8   72 02            jb short .002667ec
 *  002667ea   8b12             mov edx,dword ptr ds:[edx]
 *  002667ec   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  002667ef   57               push edi
 *  002667f0   8d3c42           lea edi,dword ptr ds:[edx+eax*2]
 *  002667f3   85c9             test ecx,ecx
 *  002667f5   74 16            je short .0026680d
 *  002667f7   8b45 10          mov eax,dword ptr ss:[ebp+0x10]
 *  002667fa   0fb7d0           movzx edx,ax
 *  002667fd   8bc2             mov eax,edx
 *  002667ff   c1e2 10          shl edx,0x10
 *  00266802   0bc2             or eax,edx
 *  00266804   d1e9             shr ecx,1
 *  00266806   f3:ab            rep stos dword ptr es:[edi]
 *  00266808   13c9             adc ecx,ecx
 *  0026680a   66:f3:ab         rep stos word ptr es:[edi]
 *  0026680d   5f               pop edi
 *  0026680e   5d               pop ebp
 *  0026680f   c2 0c00          retn 0xc
 *  00266812   cc               int3
 *  00266813   cc               int3
 *
 *  Stack when enter function call:
 *  04cee270   00266870  return to .00266870 from .002667c0
 *  04cee274   00000002  jichi: arg1, ecx
 *  04cee278   00000001  jichi: arg2, always 1
 *  04cee27c   000050ac  jichi: arg3, wchar_t
 *  04cee280   04cee4fc  jichi: text address
 *  04cee284   0ead055c  arg5
 *  04cee288   0ead0568  arg6, last text when arg6 = arg5 = 2
 *  04cee28c  /04cee2c0
 *  04cee290  |00266969  return to .00266969 from .00266820
 *  04cee294  |00000001
 *  04cee298  |000050ac
 *  04cee29c  |e1466fb2
 *  04cee2a0  |072f45f0
 *
 *  Target address (edx) is at [[ecx]] when enter function.
 */

// jichi: 8/17/2013: Change return type to bool
bool InsertSiglus3Hook()
{
  const BYTE bytes[] = {
    0x8b,0x12,             // 002667d3   8b12             mov edx,dword ptr ds:[edx]
    0x8b,0x4d, 0x08,       // 002667d5   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
    0x66,0x8b,0x45, 0x10,  // 002667d8   66:8b45 10       mov ax,word ptr ss:[ebp+0x10]
    0x66,0x89,0x04,0x4a    // 002667dc   66:89044a        mov word ptr ds:[edx+ecx*2],ax ; jichi: wchar_t in ax
                           // 002667e0   5d               pop ebp
                           // 002667e1   c2 0c00          retn 0xc
  };
  enum { hook_offset = sizeof(bytes) - 4 };
  ULONG range = max(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!addr) { // jichi 8/17/2013: Add "== 0" check to prevent breaking new games
    //ConsoleOutput("Unknown SiglusEngine");
    ConsoleOutput("vnreng:Siglus3: pattern not found");
    return false;
  }

  //addr = MemDbg::findEnclosingAlignedFunction(addr, 50); // 0x002667dc - 0x002667c0 = 28
  //if (!addr) {
  //  ConsoleOutput("vnreng:Siglus3: enclosing function not found");
  //  return false;
  //}

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = pusha_eax_off - 4;
  hp.type = USING_UNICODE;
  hp.length_offset = 1;
  //hp.text_fun = SpecialHookSiglus3;

  ConsoleOutput("vnreng: INSERT Siglus3");
  NewHook(hp, L"SiglusEngine3");

  ConsoleOutput("vnreng:Siglus3: disable GDI hooks");
  DisableGDIHooks();
  return true;
}

/**
 *  jichi 8/16/2013: Insert new siglus hook
 *  See (CaoNiMaGeBi): http://tieba.baidu.com/p/2531786952
 *  Issue: floating text
 *  Example:
 *  0153588b9534fdffff8b43583bd7
 *  0153 58          add dword ptr ds:[ebx+58],edx
 *  8b95 34fdffff    mov edx,dword ptr ss:[ebp-2cc]
 *  8b43 58          mov eax,dword ptr ds:[ebx+58]
 *  3bd7             cmp edx,edi    ; hook here
 *
 *  /HW-1C@D9DB2:SiglusEngine.exe
 *  - addr: 892338 (0xd9db2)
 *  - text_fun: 0x0
 *  - function: 0
 *  - hook_len: 0
 *  - ind: 0
 *  - length_offset: 1
 *  - module: 356004490 (0x1538328a)
 *  - off: 4294967264 (0xffffffe0L, 0x-20)
 *  - recover_len: 0
 *  - split: 0
 *  - split_ind: 0
 *  - type: 66   (0x42)
 *
 *  10/19/2014: There are currently two patterns to find the function to render scenario text.
 *  In the future, if both of them do not work again, try the following pattern instead.
 *  It is used to infer SiglusEngine2's logic in vnragent.
 *
 *  01140f8d   56               push esi
 *  01140f8e   8d8b 0c010000    lea ecx,dword ptr ds:[ebx+0x10c]
 *  01140f94   e8 67acfcff      call .0110bc00
 *  01140f99   837f 14 08       cmp dword ptr ds:[edi+0x14],0x8
 *  01140f9d   72 04            jb short .01140fa3
 *  01140f9f   8b37             mov esi,dword ptr ds:[edi]
 *  01140fa1   eb 02            jmp short .01140fa5
 *
 *  Type1 (聖娼女):
 *
 *  013aac6c   cc               int3
 *  013aac6d   cc               int3
 *  013aac6e   cc               int3
 *  013aac6f   cc               int3
 *  013aac70   55               push ebp    ; jichi: vnragent hooked here
 *  013aac71   8bec             mov ebp,esp
 *  013aac73   6a ff            push -0x1
 *  013aac75   68 d8306101      push .016130d8
 *  013aac7a   64:a1 00000000   mov eax,dword ptr fs:[0]
 *  013aac80   50               push eax
 *  013aac81   81ec dc020000    sub esp,0x2dc
 *  013aac87   a1 90f46a01      mov eax,dword ptr ds:[0x16af490]
 *  013aac8c   33c5             xor eax,ebp
 *  013aac8e   8945 f0          mov dword ptr ss:[ebp-0x10],eax
 *  013aac91   53               push ebx
 *  013aac92   56               push esi
 *  013aac93   57               push edi
 *  013aac94   50               push eax
 *  013aac95   8d45 f4          lea eax,dword ptr ss:[ebp-0xc]
 *  013aac98   64:a3 00000000   mov dword ptr fs:[0],eax
 *  013aac9e   8b45 0c          mov eax,dword ptr ss:[ebp+0xc]
 *  013aaca1   8b5d 08          mov ebx,dword ptr ss:[ebp+0x8]
 *  013aaca4   8bf9             mov edi,ecx
 *  013aaca6   8b77 10          mov esi,dword ptr ds:[edi+0x10]
 *  013aaca9   89bd 20fdffff    mov dword ptr ss:[ebp-0x2e0],edi
 *  013aacaf   8985 18fdffff    mov dword ptr ss:[ebp-0x2e8],eax
 *  013aacb5   85f6             test esi,esi
 *  013aacb7   0f84 77040000    je .013ab134
 *  013aacbd   8b93 18010000    mov edx,dword ptr ds:[ebx+0x118]
 *  013aacc3   2b93 14010000    sub edx,dword ptr ds:[ebx+0x114]
 *  013aacc9   8d8b 14010000    lea ecx,dword ptr ds:[ebx+0x114]
 *  013aaccf   b8 67666666      mov eax,0x66666667
 *  013aacd4   f7ea             imul edx
 *  013aacd6   c1fa 08          sar edx,0x8
 *  013aacd9   8bc2             mov eax,edx
 *  013aacdb   c1e8 1f          shr eax,0x1f
 *  013aacde   03c2             add eax,edx
 *  013aace0   03c6             add eax,esi
 *  013aace2   50               push eax
 *  013aace3   e8 5896fcff      call .01374340
 *  013aace8   837f 14 08       cmp dword ptr ds:[edi+0x14],0x8
 *  013aacec   72 04            jb short .013aacf2
 *  013aacee   8b07             mov eax,dword ptr ds:[edi]
 *  013aacf0   eb 02            jmp short .013aacf4
 *  013aacf2   8bc7             mov eax,edi
 *  013aacf4   8985 24fdffff    mov dword ptr ss:[ebp-0x2dc],eax
 *  013aacfa   8b57 14          mov edx,dword ptr ds:[edi+0x14]
 *  013aacfd   83fa 08          cmp edx,0x8
 *  013aad00   72 04            jb short .013aad06
 *  013aad02   8b0f             mov ecx,dword ptr ds:[edi]
 *  013aad04   eb 02            jmp short .013aad08
 *  013aad06   8bcf             mov ecx,edi
 *  013aad08   8b47 10          mov eax,dword ptr ds:[edi+0x10]
 *  013aad0b   8bb5 24fdffff    mov esi,dword ptr ss:[ebp-0x2dc]
 *  013aad11   03c0             add eax,eax
 *  013aad13   03c8             add ecx,eax
 *  013aad15   3bf1             cmp esi,ecx
 *  013aad17   0f84 17040000    je .013ab134
 *  013aad1d   c785 34fdffff 00>mov dword ptr ss:[ebp-0x2cc],0x0
 *  013aad27   c785 2cfdffff ff>mov dword ptr ss:[ebp-0x2d4],-0x1
 *  013aad31   89b5 1cfdffff    mov dword ptr ss:[ebp-0x2e4],esi
 *  013aad37   83fa 08          cmp edx,0x8
 *  013aad3a   72 04            jb short .013aad40
 *  013aad3c   8b0f             mov ecx,dword ptr ds:[edi]
 *  013aad3e   eb 02            jmp short .013aad42
 *  013aad40   8bcf             mov ecx,edi
 *  013aad42   03c1             add eax,ecx
 *  013aad44   8d8d 2cfdffff    lea ecx,dword ptr ss:[ebp-0x2d4]
 *  013aad4a   51               push ecx
 *  013aad4b   8d95 34fdffff    lea edx,dword ptr ss:[ebp-0x2cc]
 *  013aad51   52               push edx
 *  013aad52   50               push eax
 *  013aad53   8d85 24fdffff    lea eax,dword ptr ss:[ebp-0x2dc]
 *  013aad59   50               push eax
 *  013aad5a   e8 b183faff      call .01353110
 *  013aad5f   8bb5 2cfdffff    mov esi,dword ptr ss:[ebp-0x2d4]
 *  013aad65   83c4 10          add esp,0x10
 *  013aad68   83fe 0a          cmp esi,0xa
 *  013aad6b   75 09            jnz short .013aad76
 *  013aad6d   8bcb             mov ecx,ebx
 *  013aad6f   e8 ac050000      call .013ab320
 *  013aad74  ^eb 84            jmp short .013aacfa
 *  013aad76   83fe 07          cmp esi,0x7
 *  013aad79   75 2a            jnz short .013aada5
 *  013aad7b   33c9             xor ecx,ecx
 *  013aad7d   33c0             xor eax,eax
 *  013aad7f   66:898b ec000000 mov word ptr ds:[ebx+0xec],cx
 *  013aad86   8bcb             mov ecx,ebx
 *  013aad88   8983 e8000000    mov dword ptr ds:[ebx+0xe8],eax
 *  013aad8e   8983 f0000000    mov dword ptr ds:[ebx+0xf0],eax
 *  013aad94   e8 87050000      call .013ab320
 *  013aad99   c683 f9000000 01 mov byte ptr ds:[ebx+0xf9],0x1
 *  013aada0  ^e9 55ffffff      jmp .013aacfa
 *  013aada5   8b85 34fdffff    mov eax,dword ptr ss:[ebp-0x2cc]
 *  013aadab   85c0             test eax,eax
 *  013aadad   75 37            jnz short .013aade6
 *  013aadaf   85f6             test esi,esi
 *  013aadb1  ^0f84 43ffffff    je .013aacfa
 *  013aadb7   85c0             test eax,eax
 *  013aadb9   75 2b            jnz short .013aade6
 *  013aadbb   f605 c0be9f05 01 test byte ptr ds:[0x59fbec0],0x1
 *  013aadc2   75 0c            jnz short .013aadd0
 *  013aadc4   830d c0be9f05 01 or dword ptr ds:[0x59fbec0],0x1
 *  013aadcb   e8 f02a0b00      call .0145d8c0
 *  013aadd0   0fb7d6           movzx edx,si
 *  013aadd3   80ba c0be9e05 01 cmp byte ptr ds:[edx+0x59ebec0],0x1
 *  013aadda   75 0a            jnz short .013aade6
 *  013aaddc   8b43 68          mov eax,dword ptr ds:[ebx+0x68]
 *  013aaddf   99               cdq
 *  013aade0   2bc2             sub eax,edx
 *  013aade2   d1f8             sar eax,1
 *  013aade4   eb 03            jmp short .013aade9
 *  013aade6   8b43 68          mov eax,dword ptr ds:[ebx+0x68]
 *  013aade9   8b8b a0000000    mov ecx,dword ptr ds:[ebx+0xa0]
 *  013aadef   8b53 18          mov edx,dword ptr ds:[ebx+0x18]
 *  013aadf2   8985 30fdffff    mov dword ptr ss:[ebp-0x2d0],eax
 *  013aadf8   0343 58          add eax,dword ptr ds:[ebx+0x58]
 *  013aadfb   03d1             add edx,ecx
 *  013aadfd   3bc2             cmp eax,edx
 *  013aadff   7f 0f            jg short .013aae10
 *  013aae01   3bc1             cmp eax,ecx
 *  013aae03   7e 30            jle short .013aae35
 *  013aae05   8bc6             mov eax,esi
 *  013aae07   e8 94faffff      call .013aa8a0
 *  013aae0c   84c0             test al,al
 *  013aae0e   75 25            jnz short .013aae35
 *  013aae10   8bcb             mov ecx,ebx
 *  013aae12   e8 09050000      call .013ab320
 *  013aae17   83bd 34fdffff 00 cmp dword ptr ss:[ebp-0x2cc],0x0
 *  013aae1e   75 15            jnz short .013aae35
 *  013aae20   83fe 20          cmp esi,0x20
 *  013aae23  ^0f84 d1feffff    je .013aacfa
 *  013aae29   81fe 00300000    cmp esi,0x3000
 *  013aae2f  ^0f84 c5feffff    je .013aacfa
 *  013aae35   8b43 5c          mov eax,dword ptr ds:[ebx+0x5c]
 *  013aae38   3b83 a4000000    cmp eax,dword ptr ds:[ebx+0xa4]
 *  013aae3e   0f8d 7e020000    jge .013ab0c2
 *  013aae44   8d8d 38fdffff    lea ecx,dword ptr ss:[ebp-0x2c8]
 *  013aae4a   51               push ecx
 *  013aae4b   e8 30e4ffff      call .013a9280
 *  013aae50   c745 fc 01000000 mov dword ptr ss:[ebp-0x4],0x1
 *  013aae57   8b43 74          mov eax,dword ptr ds:[ebx+0x74]
 *  013aae5a   8b0d 88b26c01    mov ecx,dword ptr ds:[0x16cb288]
 *  013aae60   83f8 ff          cmp eax,-0x1
 *  013aae63   74 04            je short .013aae69
 *  013aae65   8bd0             mov edx,eax
 *  013aae67   eb 19            jmp short .013aae82
 *  013aae69   80b9 60010000 00 cmp byte ptr ds:[ecx+0x160],0x0
 *  013aae70   74 0d            je short .013aae7f
 *  013aae72   8b83 e0000000    mov eax,dword ptr ds:[ebx+0xe0]
 *  013aae78   8bd0             mov edx,eax
 *  013aae7a   83f8 ff          cmp eax,-0x1
 *  013aae7d   75 03            jnz short .013aae82
 *  013aae7f   8b53 24          mov edx,dword ptr ds:[ebx+0x24]
 *  013aae82   8b43 78          mov eax,dword ptr ds:[ebx+0x78]
 *  013aae85   83f8 ff          cmp eax,-0x1
 *  013aae88   75 17            jnz short .013aaea1
 *  013aae8a   80b9 60010000 00 cmp byte ptr ds:[ecx+0x160],0x0
 *  013aae91   74 0b            je short .013aae9e
 *  013aae93   8b83 e4000000    mov eax,dword ptr ds:[ebx+0xe4]
 *  013aae99   83f8 ff          cmp eax,-0x1
 *  013aae9c   75 03            jnz short .013aaea1
 *  013aae9e   8b43 28          mov eax,dword ptr ds:[ebx+0x28]
 *  013aaea1   8b4b 60          mov ecx,dword ptr ds:[ebx+0x60]
 *  013aaea4   8bb5 34fdffff    mov esi,dword ptr ss:[ebp-0x2cc]
 *  013aaeaa   034b 58          add ecx,dword ptr ds:[ebx+0x58]
 *  013aaead   8b7b 68          mov edi,dword ptr ds:[ebx+0x68]
 *  013aaeb0   8985 28fdffff    mov dword ptr ss:[ebp-0x2d8],eax
 *  013aaeb6   8b43 5c          mov eax,dword ptr ds:[ebx+0x5c]
 *  013aaeb9   0343 64          add eax,dword ptr ds:[ebx+0x64]
 *  013aaebc   83fe 01          cmp esi,0x1
 *  013aaebf   75 02            jnz short .013aaec3
 *  013aaec1   33d2             xor edx,edx
 *  013aaec3   80bb fa000000 00 cmp byte ptr ds:[ebx+0xfa],0x0
 *  013aaeca   89b5 38fdffff    mov dword ptr ss:[ebp-0x2c8],esi
 *  013aaed0   8bb5 2cfdffff    mov esi,dword ptr ss:[ebp-0x2d4]
 *  013aaed6   8995 44fdffff    mov dword ptr ss:[ebp-0x2bc],edx
 *  013aaedc   8b95 28fdffff    mov edx,dword ptr ss:[ebp-0x2d8]
 *  013aaee2   89b5 3cfdffff    mov dword ptr ss:[ebp-0x2c4],esi
 *  013aaee8   89bd 40fdffff    mov dword ptr ss:[ebp-0x2c0],edi
 *  013aaeee   8995 48fdffff    mov dword ptr ss:[ebp-0x2b8],edx
 *  013aaef4   898d 4cfdffff    mov dword ptr ss:[ebp-0x2b4],ecx
 *  013aaefa   8985 50fdffff    mov dword ptr ss:[ebp-0x2b0],eax
 *  013aaf00   74 19            je short .013aaf1b
 *  013aaf02   8b43 58          mov eax,dword ptr ds:[ebx+0x58]
 *  013aaf05   8b4b 5c          mov ecx,dword ptr ds:[ebx+0x5c]
 *  013aaf08   8983 fc000000    mov dword ptr ds:[ebx+0xfc],eax
 *  013aaf0e   898b 00010000    mov dword ptr ds:[ebx+0x100],ecx
 *  013aaf14   c683 fa000000 00 mov byte ptr ds:[ebx+0xfa],0x0
 *  013aaf1b   8b53 6c          mov edx,dword ptr ds:[ebx+0x6c]
 *  013aaf1e   0395 30fdffff    add edx,dword ptr ss:[ebp-0x2d0]
 *  013aaf24   33ff             xor edi,edi
 *  013aaf26   0153 58          add dword ptr ds:[ebx+0x58],edx
 *  013aaf29   8b95 34fdffff    mov edx,dword ptr ss:[ebp-0x2cc]
 *  013aaf2f   8b43 58          mov eax,dword ptr ds:[ebx+0x58]
 *  013aaf32   3bd7             cmp edx,edi             ; jichi: hook here
 *  013aaf34   75 4b            jnz short .013aaf81
 *  013aaf36   81fe 0c300000    cmp esi,0x300c  ; jichi 10/18/2014: searched here found the new siglus function
 *  013aaf3c   74 10            je short .013aaf4e
 *  013aaf3e   81fe 0e300000    cmp esi,0x300e
 *  013aaf44   74 08            je short .013aaf4e
 *  013aaf46   81fe 08ff0000    cmp esi,0xff08
 *  013aaf4c   75 33            jnz short .013aaf81
 *  013aaf4e   80bb f9000000 00 cmp byte ptr ds:[ebx+0xf9],0x0
 *  013aaf55   74 19            je short .013aaf70
 *  013aaf57   8983 e8000000    mov dword ptr ds:[ebx+0xe8],eax
 *  013aaf5d   66:89b3 ec000000 mov word ptr ds:[ebx+0xec],si
 *  013aaf64   c783 f0000000 01>mov dword ptr ds:[ebx+0xf0],0x1
 *  013aaf6e   eb 11            jmp short .013aaf81
 *  013aaf70   0fb783 ec000000  movzx eax,word ptr ds:[ebx+0xec]
 *  013aaf77   3bf0             cmp esi,eax
 *  013aaf79   75 06            jnz short .013aaf81
 *  013aaf7b   ff83 f0000000    inc dword ptr ds:[ebx+0xf0]
 *  013aaf81   8b8b f0000000    mov ecx,dword ptr ds:[ebx+0xf0]
 *  013aaf87   3bcf             cmp ecx,edi
 *  013aaf89   7e 71            jle short .013aaffc
 *  013aaf8b   3bd7             cmp edx,edi
 *  013aaf8d   75 50            jnz short .013aafdf
 *  013aaf8f   0fb783 ec000000  movzx eax,word ptr ds:[ebx+0xec]
 *  013aaf96   ba 0c300000      mov edx,0x300c
 *  013aaf9b   66:3bc2          cmp ax,dx
 *  013aaf9e   75 0f            jnz short .013aafaf
 *  013aafa0   81fe 0d300000    cmp esi,0x300d
 *  013aafa6   75 07            jnz short .013aafaf
 *  013aafa8   49               dec ecx
 *  013aafa9   898b f0000000    mov dword ptr ds:[ebx+0xf0],ecx
 *  013aafaf   b9 0e300000      mov ecx,0x300e
 *  013aafb4   66:3bc1          cmp ax,cx
 *  013aafb7   75 0e            jnz short .013aafc7
 *  013aafb9   81fe 0f300000    cmp esi,0x300f
 *  013aafbf   75 06            jnz short .013aafc7
 *  013aafc1   ff8b f0000000    dec dword ptr ds:[ebx+0xf0]
 *  013aafc7   ba 08ff0000      mov edx,0xff08
 *  013aafcc   66:3bc2          cmp ax,dx
 *  013aafcf   75 0e            jnz short .013aafdf
 *  013aafd1   81fe 09ff0000    cmp esi,0xff09
 *  013aafd7   75 06            jnz short .013aafdf
 *  013aafd9   ff8b f0000000    dec dword ptr ds:[ebx+0xf0]
 *  013aafdf   39bb f0000000    cmp dword ptr ds:[ebx+0xf0],edi
 *  013aafe5   75 15            jnz short .013aaffc
 *  013aafe7   33c0             xor eax,eax
 *  013aafe9   89bb e8000000    mov dword ptr ds:[ebx+0xe8],edi
 *  013aafef   66:8983 ec000000 mov word ptr ds:[ebx+0xec],ax
 *  013aaff6   89bb f0000000    mov dword ptr ds:[ebx+0xf0],edi
 *  013aaffc   8d8d 38fdffff    lea ecx,dword ptr ss:[ebp-0x2c8]
 *  013ab002   8dbb 14010000    lea edi,dword ptr ds:[ebx+0x114]
 *  013ab008   e8 b390fcff      call .013740c0
 *  013ab00d   33ff             xor edi,edi
 *  013ab00f   39bd 34fdffff    cmp dword ptr ss:[ebp-0x2cc],edi
 *  013ab015   75 0e            jnz short .013ab025
 *  013ab017   56               push esi
 *  013ab018   8d83 a8000000    lea eax,dword ptr ds:[ebx+0xa8]
 *  013ab01e   e8 5d080000      call .013ab880
 *  013ab023   eb 65            jmp short .013ab08a
 *  013ab025   8b85 1cfdffff    mov eax,dword ptr ss:[ebp-0x2e4]
 *  013ab02b   33c9             xor ecx,ecx
 *  013ab02d   66:894d d4       mov word ptr ss:[ebp-0x2c],cx
 *  013ab031   8b8d 24fdffff    mov ecx,dword ptr ss:[ebp-0x2dc]
 *  013ab037   c745 e8 07000000 mov dword ptr ss:[ebp-0x18],0x7
 *  013ab03e   897d e4          mov dword ptr ss:[ebp-0x1c],edi
 *  013ab041   3bc1             cmp eax,ecx
 *  013ab043   74 0d            je short .013ab052
 *  013ab045   2bc8             sub ecx,eax
 *  013ab047   d1f9             sar ecx,1
 *  013ab049   51               push ecx
 *  013ab04a   8d75 d4          lea esi,dword ptr ss:[ebp-0x2c]
 *  013ab04d   e8 de72f2ff      call .012d2330
 *  013ab052   6a ff            push -0x1
 *  013ab054   57               push edi
 *  013ab055   8d55 d4          lea edx,dword ptr ss:[ebp-0x2c]
 *  013ab058   52               push edx
 *  013ab059   8db3 a8000000    lea esi,dword ptr ds:[ebx+0xa8]
 *  013ab05f   c645 fc 02       mov byte ptr ss:[ebp-0x4],0x2
 *  013ab063   e8 3879f2ff      call .012d29a0
 *  013ab068   837d e8 08       cmp dword ptr ss:[ebp-0x18],0x8
 *  013ab06c   72 0c            jb short .013ab07a
 *  013ab06e   8b45 d4          mov eax,dword ptr ss:[ebp-0x2c]
 *  013ab071   50               push eax
 *  013ab072   e8 5fbe1900      call .01546ed6
 *  013ab077   83c4 04          add esp,0x4
 *  013ab07a   33c9             xor ecx,ecx
 *  013ab07c   c745 e8 07000000 mov dword ptr ss:[ebp-0x18],0x7
 *  013ab083   897d e4          mov dword ptr ss:[ebp-0x1c],edi
 *  013ab086   66:894d d4       mov word ptr ss:[ebp-0x2c],cx
 *  013ab08a   8bbd 20fdffff    mov edi,dword ptr ss:[ebp-0x2e0]
 *  013ab090   c683 f9000000 00 mov byte ptr ds:[ebx+0xf9],0x0
 *  013ab097   8d95 88feffff    lea edx,dword ptr ss:[ebp-0x178]
 *  013ab09d   52               push edx
 *  013ab09e   c745 fc 03000000 mov dword ptr ss:[ebp-0x4],0x3
 *  013ab0a5   e8 d6c70800      call .01437880
 *  013ab0aa   8d85 58fdffff    lea eax,dword ptr ss:[ebp-0x2a8]
 *  013ab0b0   50               push eax
 *  013ab0b1   c745 fc ffffffff mov dword ptr ss:[ebp-0x4],-0x1
 *  013ab0b8   e8 c3c70800      call .01437880
 *  013ab0bd  ^e9 38fcffff      jmp .013aacfa
 *  013ab0c2   8b9d 18fdffff    mov ebx,dword ptr ss:[ebp-0x2e8]
 *  013ab0c8   85db             test ebx,ebx
 *  013ab0ca   74 68            je short .013ab134
 *  013ab0cc   837f 14 08       cmp dword ptr ds:[edi+0x14],0x8
 *  013ab0d0   72 04            jb short .013ab0d6
 *  013ab0d2   8b07             mov eax,dword ptr ds:[edi]
 *  013ab0d4   eb 02            jmp short .013ab0d8
 *  013ab0d6   8bc7             mov eax,edi
 *  013ab0d8   8b4f 10          mov ecx,dword ptr ds:[edi+0x10]
 *  013ab0db   8d0448           lea eax,dword ptr ds:[eax+ecx*2]
 *  013ab0de   8b8d 1cfdffff    mov ecx,dword ptr ss:[ebp-0x2e4]
 *  013ab0e4   33d2             xor edx,edx
 *  013ab0e6   c745 cc 07000000 mov dword ptr ss:[ebp-0x34],0x7
 *  013ab0ed   c745 c8 00000000 mov dword ptr ss:[ebp-0x38],0x0
 *  013ab0f4   66:8955 b8       mov word ptr ss:[ebp-0x48],dx
 *  013ab0f8   3bc8             cmp ecx,eax
 *  013ab0fa   74 0f            je short .013ab10b
 *  013ab0fc   2bc1             sub eax,ecx
 *  013ab0fe   d1f8             sar eax,1
 *  013ab100   50               push eax
 *  013ab101   8bc1             mov eax,ecx
 *  013ab103   8d75 b8          lea esi,dword ptr ss:[ebp-0x48]
 *  013ab106   e8 2572f2ff      call .012d2330
 *  013ab10b   6a 00            push 0x0
 *  013ab10d   8d45 b8          lea eax,dword ptr ss:[ebp-0x48]
 *  013ab110   50               push eax
 *  013ab111   83c8 ff          or eax,0xffffffff
 *  013ab114   8bcb             mov ecx,ebx
 *  013ab116   c745 fc 00000000 mov dword ptr ss:[ebp-0x4],0x0
 *  013ab11d   e8 2e6ef2ff      call .012d1f50
 *  013ab122   837d cc 08       cmp dword ptr ss:[ebp-0x34],0x8
 *  013ab126   72 0c            jb short .013ab134
 *  013ab128   8b4d b8          mov ecx,dword ptr ss:[ebp-0x48]
 *  013ab12b   51               push ecx
 *  013ab12c   e8 a5bd1900      call .01546ed6
 *  013ab131   83c4 04          add esp,0x4
 *  013ab134   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  013ab137   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  013ab13e   59               pop ecx
 *  013ab13f   5f               pop edi
 *  013ab140   5e               pop esi
 *  013ab141   5b               pop ebx
 *  013ab142   8b4d f0          mov ecx,dword ptr ss:[ebp-0x10]
 *  013ab145   33cd             xor ecx,ebp
 *  013ab147   e8 6ab30e00      call .014964b6
 *  013ab14c   8be5             mov esp,ebp
 *  013ab14e   5d               pop ebp
 *  013ab14f   c2 0800          retn 0x8
 *  013ab152   cc               int3
 *  013ab153   cc               int3
 *  013ab154   cc               int3
 *
 *  10/18/2014 Type2: リア充クラスメイト孕ませ催眠
 *
 *  01140edb   cc               int3
 *  01140edc   cc               int3
 *  01140edd   cc               int3
 *  01140ede   cc               int3
 *  01140edf   cc               int3
 *  01140ee0   55               push ebp
 *  01140ee1   8bec             mov ebp,esp
 *  01140ee3   6a ff            push -0x1
 *  01140ee5   68 c6514a01      push .014a51c6
 *  01140eea   64:a1 00000000   mov eax,dword ptr fs:[0]
 *  01140ef0   50               push eax
 *  01140ef1   81ec dc020000    sub esp,0x2dc
 *  01140ef7   a1 10745501      mov eax,dword ptr ds:[0x1557410]
 *  01140efc   33c5             xor eax,ebp
 *  01140efe   8945 f0          mov dword ptr ss:[ebp-0x10],eax
 *  01140f01   53               push ebx
 *  01140f02   56               push esi
 *  01140f03   57               push edi
 *  01140f04   50               push eax
 *  01140f05   8d45 f4          lea eax,dword ptr ss:[ebp-0xc]
 *  01140f08   64:a3 00000000   mov dword ptr fs:[0],eax
 *  01140f0e   8bd9             mov ebx,ecx
 *  01140f10   8b7d 08          mov edi,dword ptr ss:[ebp+0x8]
 *  01140f13   837f 10 00       cmp dword ptr ds:[edi+0x10],0x0
 *  01140f17   8b45 0c          mov eax,dword ptr ss:[ebp+0xc]
 *  01140f1a   8985 1cfdffff    mov dword ptr ss:[ebp-0x2e4],eax
 *  01140f20   8d47 10          lea eax,dword ptr ds:[edi+0x10]
 *  01140f23   89bd 38fdffff    mov dword ptr ss:[ebp-0x2c8],edi
 *  01140f29   8985 20fdffff    mov dword ptr ss:[ebp-0x2e0],eax
 *  01140f2f   0f84 2a050000    je .0114145f
 *  01140f35   8b8b 10010000    mov ecx,dword ptr ds:[ebx+0x110]
 *  01140f3b   b8 67666666      mov eax,0x66666667
 *  01140f40   2b8b 0c010000    sub ecx,dword ptr ds:[ebx+0x10c]
 *  01140f46   f7e9             imul ecx
 *  01140f48   8b85 20fdffff    mov eax,dword ptr ss:[ebp-0x2e0]
 *  01140f4e   8b8b 14010000    mov ecx,dword ptr ds:[ebx+0x114]
 *  01140f54   2b8b 0c010000    sub ecx,dword ptr ds:[ebx+0x10c]
 *  01140f5a   c1fa 08          sar edx,0x8
 *  01140f5d   8bf2             mov esi,edx
 *  01140f5f   c1ee 1f          shr esi,0x1f
 *  01140f62   03f2             add esi,edx
 *  01140f64   0330             add esi,dword ptr ds:[eax]
 *  01140f66   b8 67666666      mov eax,0x66666667
 *  01140f6b   f7e9             imul ecx
 *  01140f6d   c1fa 08          sar edx,0x8
 *  01140f70   8bc2             mov eax,edx
 *  01140f72   c1e8 1f          shr eax,0x1f
 *  01140f75   03c2             add eax,edx
 *  01140f77   3bc6             cmp eax,esi
 *  01140f79   73 1e            jnb short .01140f99
 *  01140f7b   81fe 66666600    cmp esi,0x666666                         ; unicode "s the data.
 *  01140f81   76 0a            jbe short .01140f8d
 *  01140f83   68 c00f4f01      push .014f0fc0                           ; ascii "vector<t> too long"
 *  01140f88   e8 b1a30e00      call .0122b33e
 *  01140f8d   56               push esi
 *  01140f8e   8d8b 0c010000    lea ecx,dword ptr ds:[ebx+0x10c]
 *  01140f94   e8 67acfcff      call .0110bc00
 *  01140f99   837f 14 08       cmp dword ptr ds:[edi+0x14],0x8
 *  01140f9d   72 04            jb short .01140fa3
 *  01140f9f   8b37             mov esi,dword ptr ds:[edi]
 *  01140fa1   eb 02            jmp short .01140fa5
 *  01140fa3   8bf7             mov esi,edi
 *  01140fa5   89b5 34fdffff    mov dword ptr ss:[ebp-0x2cc],esi
 *  01140fab   eb 03            jmp short .01140fb0
 *  01140fad   8d49 00          lea ecx,dword ptr ds:[ecx]
 *  01140fb0   8b57 14          mov edx,dword ptr ds:[edi+0x14]
 *  01140fb3   83fa 08          cmp edx,0x8
 *  01140fb6   72 04            jb short .01140fbc
 *  01140fb8   8b07             mov eax,dword ptr ds:[edi]
 *  01140fba   eb 02            jmp short .01140fbe
 *  01140fbc   8bc7             mov eax,edi
 *  01140fbe   8b8d 20fdffff    mov ecx,dword ptr ss:[ebp-0x2e0]
 *  01140fc4   8b09             mov ecx,dword ptr ds:[ecx]
 *  01140fc6   03c9             add ecx,ecx
 *  01140fc8   03c1             add eax,ecx
 *  01140fca   3bf0             cmp esi,eax
 *  01140fcc   0f84 8d040000    je .0114145f
 *  01140fd2   8b85 38fdffff    mov eax,dword ptr ss:[ebp-0x2c8]
 *  01140fd8   8bfe             mov edi,esi
 *  01140fda   c785 3cfdffff 00>mov dword ptr ss:[ebp-0x2c4],0x0
 *  01140fe4   c785 2cfdffff ff>mov dword ptr ss:[ebp-0x2d4],-0x1
 *  01140fee   83fa 08          cmp edx,0x8
 *  01140ff1   72 02            jb short .01140ff5
 *  01140ff3   8b00             mov eax,dword ptr ds:[eax]
 *  01140ff5   03c1             add eax,ecx
 *  01140ff7   8d95 3cfdffff    lea edx,dword ptr ss:[ebp-0x2c4]
 *  01140ffd   8d8d 2cfdffff    lea ecx,dword ptr ss:[ebp-0x2d4]
 *  01141003   51               push ecx
 *  01141004   50               push eax
 *  01141005   8d8d 34fdffff    lea ecx,dword ptr ss:[ebp-0x2cc]
 *  0114100b   e8 e033fbff      call .010f43f0
 *  01141010   8bb5 2cfdffff    mov esi,dword ptr ss:[ebp-0x2d4]
 *  01141016   83c4 08          add esp,0x8
 *  01141019   83fe 0a          cmp esi,0xa
 *  0114101c   75 18            jnz short .01141036
 *  0114101e   8bcb             mov ecx,ebx
 *  01141020   e8 2b060000      call .01141650
 *  01141025   8bb5 34fdffff    mov esi,dword ptr ss:[ebp-0x2cc]
 *  0114102b   8bbd 38fdffff    mov edi,dword ptr ss:[ebp-0x2c8]
 *  01141031  ^e9 7affffff      jmp .01140fb0
 *  01141036   83fe 07          cmp esi,0x7
 *  01141039   75 38            jnz short .01141073
 *  0114103b   33c0             xor eax,eax
 *  0114103d   c783 e0000000 00>mov dword ptr ds:[ebx+0xe0],0x0
 *  01141047   8bcb             mov ecx,ebx
 *  01141049   66:8983 e4000000 mov word ptr ds:[ebx+0xe4],ax
 *  01141050   8983 e8000000    mov dword ptr ds:[ebx+0xe8],eax
 *  01141056   e8 f5050000      call .01141650
 *  0114105b   8bb5 34fdffff    mov esi,dword ptr ss:[ebp-0x2cc]
 *  01141061   8bbd 38fdffff    mov edi,dword ptr ss:[ebp-0x2c8]
 *  01141067   c683 f1000000 01 mov byte ptr ds:[ebx+0xf1],0x1
 *  0114106e  ^e9 3dffffff      jmp .01140fb0
 *  01141073   8b85 3cfdffff    mov eax,dword ptr ss:[ebp-0x2c4]
 *  01141079   85c0             test eax,eax
 *  0114107b   75 36            jnz short .011410b3
 *  0114107d   85f6             test esi,esi
 *  0114107f   74 7f            je short .01141100
 *  01141081   85c0             test eax,eax
 *  01141083   75 2e            jnz short .011410b3
 *  01141085   a1 00358905      mov eax,dword ptr ds:[0x5893500]
 *  0114108a   a8 01            test al,0x1
 *  0114108c   75 0d            jnz short .0114109b
 *  0114108e   83c8 01          or eax,0x1
 *  01141091   a3 00358905      mov dword ptr ds:[0x5893500],eax
 *  01141096   e8 65160b00      call .011f2700
 *  0114109b   0fb7c6           movzx eax,si
 *  0114109e   80b8 10358905 01 cmp byte ptr ds:[eax+0x5893510],0x1
 *  011410a5   75 0c            jnz short .011410b3
 *  011410a7   8b43 68          mov eax,dword ptr ds:[ebx+0x68]
 *  011410aa   99               cdq
 *  011410ab   2bc2             sub eax,edx
 *  011410ad   8bc8             mov ecx,eax
 *  011410af   d1f9             sar ecx,1
 *  011410b1   eb 03            jmp short .011410b6
 *  011410b3   8b4b 68          mov ecx,dword ptr ds:[ebx+0x68]
 *  011410b6   8b43 18          mov eax,dword ptr ds:[ebx+0x18]
 *  011410b9   8b93 a0000000    mov edx,dword ptr ds:[ebx+0xa0]
 *  011410bf   03c2             add eax,edx
 *  011410c1   898d 28fdffff    mov dword ptr ss:[ebp-0x2d8],ecx
 *  011410c7   034b 58          add ecx,dword ptr ds:[ebx+0x58]
 *  011410ca   3bc8             cmp ecx,eax
 *  011410cc   7f 0f            jg short .011410dd
 *  011410ce   3bca             cmp ecx,edx
 *  011410d0   7e 3f            jle short .01141111
 *  011410d2   8bce             mov ecx,esi
 *  011410d4   e8 37faffff      call .01140b10
 *  011410d9   84c0             test al,al
 *  011410db   75 34            jnz short .01141111
 *  011410dd   8bcb             mov ecx,ebx
 *  011410df   e8 6c050000      call .01141650
 *  011410e4   83bd 3cfdffff 00 cmp dword ptr ss:[ebp-0x2c4],0x0
 *  011410eb   75 24            jnz short .01141111
 *  011410ed   83fe 20          cmp esi,0x20
 *  011410f0   74 0e            je short .01141100
 *  011410f2   81fe 00300000    cmp esi,0x3000
 *  011410f8   75 17            jnz short .01141111
 *  011410fa   8d9b 00000000    lea ebx,dword ptr ds:[ebx]
 *  01141100   8bb5 34fdffff    mov esi,dword ptr ss:[ebp-0x2cc]
 *  01141106   8bbd 38fdffff    mov edi,dword ptr ss:[ebp-0x2c8]
 *  0114110c  ^e9 9ffeffff      jmp .01140fb0
 *  01141111   8b43 5c          mov eax,dword ptr ds:[ebx+0x5c]
 *  01141114   3b83 a4000000    cmp eax,dword ptr ds:[ebx+0xa4]
 *  0114111a   0f8d cb020000    jge .011413eb
 *  01141120   8d8d 40fdffff    lea ecx,dword ptr ss:[ebp-0x2c0]
 *  01141126   e8 d5e3ffff      call .0113f500
 *  0114112b   c745 fc 01000000 mov dword ptr ss:[ebp-0x4],0x1
 *  01141132   8b4b 74          mov ecx,dword ptr ds:[ebx+0x74]
 *  01141135   8b15 98285701    mov edx,dword ptr ds:[0x1572898]
 *  0114113b   898d 30fdffff    mov dword ptr ss:[ebp-0x2d0],ecx
 *  01141141   83f9 ff          cmp ecx,-0x1
 *  01141144   75 23            jnz short .01141169
 *  01141146   80ba 58010000 00 cmp byte ptr ds:[edx+0x158],0x0
 *  0114114d   74 11            je short .01141160
 *  0114114f   8b8b d8000000    mov ecx,dword ptr ds:[ebx+0xd8]
 *  01141155   898d 30fdffff    mov dword ptr ss:[ebp-0x2d0],ecx
 *  0114115b   83f9 ff          cmp ecx,-0x1
 *  0114115e   75 09            jnz short .01141169
 *  01141160   8b43 24          mov eax,dword ptr ds:[ebx+0x24]
 *  01141163   8985 30fdffff    mov dword ptr ss:[ebp-0x2d0],eax
 *  01141169   8b43 78          mov eax,dword ptr ds:[ebx+0x78]
 *  0114116c   8985 24fdffff    mov dword ptr ss:[ebp-0x2dc],eax
 *  01141172   83f8 ff          cmp eax,-0x1
 *  01141175   75 23            jnz short .0114119a
 *  01141177   80ba 58010000 00 cmp byte ptr ds:[edx+0x158],0x0
 *  0114117e   74 11            je short .01141191
 *  01141180   8b83 dc000000    mov eax,dword ptr ds:[ebx+0xdc]
 *  01141186   8985 24fdffff    mov dword ptr ss:[ebp-0x2dc],eax
 *  0114118c   83f8 ff          cmp eax,-0x1
 *  0114118f   75 09            jnz short .0114119a
 *  01141191   8b43 28          mov eax,dword ptr ds:[ebx+0x28]
 *  01141194   8985 24fdffff    mov dword ptr ss:[ebp-0x2dc],eax
 *  0114119a   8b53 64          mov edx,dword ptr ds:[ebx+0x64]
 *  0114119d   0353 5c          add edx,dword ptr ds:[ebx+0x5c]
 *  011411a0   8b4b 60          mov ecx,dword ptr ds:[ebx+0x60]
 *  011411a3   034b 58          add ecx,dword ptr ds:[ebx+0x58]
 *  011411a6   83bd 3cfdffff 01 cmp dword ptr ss:[ebp-0x2c4],0x1
 *  011411ad   8bb5 30fdffff    mov esi,dword ptr ss:[ebp-0x2d0]
 *  011411b3   8b43 68          mov eax,dword ptr ds:[ebx+0x68]
 *  011411b6   c785 18fdffff 00>mov dword ptr ss:[ebp-0x2e8],0x0
 *  011411c0   0f44b5 18fdffff  cmove esi,dword ptr ss:[ebp-0x2e8]
 *  011411c7   80bb f2000000 00 cmp byte ptr ds:[ebx+0xf2],0x0
 *  011411ce   89b5 30fdffff    mov dword ptr ss:[ebp-0x2d0],esi
 *  011411d4   8bb5 3cfdffff    mov esi,dword ptr ss:[ebp-0x2c4]
 *  011411da   8985 48fdffff    mov dword ptr ss:[ebp-0x2b8],eax
 *  011411e0   8b85 30fdffff    mov eax,dword ptr ss:[ebp-0x2d0]
 *  011411e6   89b5 40fdffff    mov dword ptr ss:[ebp-0x2c0],esi
 *  011411ec   8bb5 2cfdffff    mov esi,dword ptr ss:[ebp-0x2d4]
 *  011411f2   8985 4cfdffff    mov dword ptr ss:[ebp-0x2b4],eax
 *  011411f8   8b85 24fdffff    mov eax,dword ptr ss:[ebp-0x2dc]
 *  011411fe   89b5 44fdffff    mov dword ptr ss:[ebp-0x2bc],esi
 *  01141204   8985 50fdffff    mov dword ptr ss:[ebp-0x2b0],eax
 *  0114120a   898d 54fdffff    mov dword ptr ss:[ebp-0x2ac],ecx
 *  01141210   8995 58fdffff    mov dword ptr ss:[ebp-0x2a8],edx
 *  01141216   74 19            je short .01141231
 *  01141218   8b43 58          mov eax,dword ptr ds:[ebx+0x58]
 *  0114121b   8983 f4000000    mov dword ptr ds:[ebx+0xf4],eax
 *  01141221   8b43 5c          mov eax,dword ptr ds:[ebx+0x5c]
 *  01141224   8983 f8000000    mov dword ptr ds:[ebx+0xf8],eax
 *  0114122a   c683 f2000000 00 mov byte ptr ds:[ebx+0xf2],0x0
 *  01141231   8b43 6c          mov eax,dword ptr ds:[ebx+0x6c]
 *  01141234   0385 28fdffff    add eax,dword ptr ss:[ebp-0x2d8]
 *  0114123a   0143 58          add dword ptr ds:[ebx+0x58],eax
 *  0114123d   8b85 3cfdffff    mov eax,dword ptr ss:[ebp-0x2c4]
 *  01141243   8b4b 58          mov ecx,dword ptr ds:[ebx+0x58]
 *  01141246   85c0             test eax,eax
 *  01141248   75 51            jnz short .0114129b
 *  0114124a   81fe 0c300000    cmp esi,0x300c  ; jichi: hook here, utf16 character is in esi
 *  01141250   74 10            je short .01141262
 *  01141252   81fe 0e300000    cmp esi,0x300e
 *  01141258   74 08            je short .01141262
 *  0114125a   81fe 08ff0000    cmp esi,0xff08
 *  01141260   75 39            jnz short .0114129b
 *  01141262   80bb f1000000 00 cmp byte ptr ds:[ebx+0xf1],0x0
 *  01141269   74 19            je short .01141284
 *  0114126b   898b e0000000    mov dword ptr ds:[ebx+0xe0],ecx
 *  01141271   66:89b3 e4000000 mov word ptr ds:[ebx+0xe4],si
 *  01141278   c783 e8000000 01>mov dword ptr ds:[ebx+0xe8],0x1
 *  01141282   eb 17            jmp short .0114129b
 *  01141284   0fb783 e4000000  movzx eax,word ptr ds:[ebx+0xe4]
 *  0114128b   3bf0             cmp esi,eax
 *  0114128d   8b85 3cfdffff    mov eax,dword ptr ss:[ebp-0x2c4]
 *  01141293   75 06            jnz short .0114129b
 *  01141295   ff83 e8000000    inc dword ptr ds:[ebx+0xe8]
 *  0114129b   8b93 e8000000    mov edx,dword ptr ds:[ebx+0xe8]
 *  011412a1   85d2             test edx,edx
 *  011412a3   7e 78            jle short .0114131d
 *  011412a5   85c0             test eax,eax
 *  011412a7   75 52            jnz short .011412fb
 *  011412a9   0fb78b e4000000  movzx ecx,word ptr ds:[ebx+0xe4]
 *  011412b0   b8 0c300000      mov eax,0x300c
 *  011412b5   66:3bc8          cmp cx,ax
 *  011412b8   75 11            jnz short .011412cb
 *  011412ba   81fe 0d300000    cmp esi,0x300d
 *  011412c0   75 09            jnz short .011412cb
 *  011412c2   8d42 ff          lea eax,dword ptr ds:[edx-0x1]
 *  011412c5   8983 e8000000    mov dword ptr ds:[ebx+0xe8],eax
 *  011412cb   b8 0e300000      mov eax,0x300e
 *  011412d0   66:3bc8          cmp cx,ax
 *  011412d3   75 0e            jnz short .011412e3
 *  011412d5   81fe 0f300000    cmp esi,0x300f
 *  011412db   75 06            jnz short .011412e3
 *  011412dd   ff8b e8000000    dec dword ptr ds:[ebx+0xe8]
 *  011412e3   b8 08ff0000      mov eax,0xff08
 *  011412e8   66:3bc8          cmp cx,ax
 *  011412eb   75 0e            jnz short .011412fb
 *  011412ed   81fe 09ff0000    cmp esi,0xff09
 *  011412f3   75 06            jnz short .011412fb
 *  011412f5   ff8b e8000000    dec dword ptr ds:[ebx+0xe8]
 *  011412fb   83bb e8000000 00 cmp dword ptr ds:[ebx+0xe8],0x0
 *  01141302   75 19            jnz short .0114131d
 *  01141304   33c0             xor eax,eax
 *  01141306   c783 e0000000 00>mov dword ptr ds:[ebx+0xe0],0x0
 *  01141310   66:8983 e4000000 mov word ptr ds:[ebx+0xe4],ax
 *  01141317   8983 e8000000    mov dword ptr ds:[ebx+0xe8],eax
 *  0114131d   8d85 40fdffff    lea eax,dword ptr ss:[ebp-0x2c0]
 *  01141323   50               push eax
 *  01141324   8d8b 0c010000    lea ecx,dword ptr ds:[ebx+0x10c]
 *  0114132a   e8 31a6fcff      call .0110b960
 *  0114132f   83bd 3cfdffff 00 cmp dword ptr ss:[ebp-0x2c4],0x0
 *  01141336   8bb5 34fdffff    mov esi,dword ptr ss:[ebp-0x2cc]
 *  0114133c   75 13            jnz short .01141351
 *  0114133e   ffb5 2cfdffff    push dword ptr ss:[ebp-0x2d4]
 *  01141344   8d8b a8000000    lea ecx,dword ptr ds:[ebx+0xa8]
 *  0114134a   e8 010a0000      call .01141d50
 *  0114134f   eb 64            jmp short .011413b5
 *  01141351   33c0             xor eax,eax
 *  01141353   c745 ec 07000000 mov dword ptr ss:[ebp-0x14],0x7
 *  0114135a   c745 e8 00000000 mov dword ptr ss:[ebp-0x18],0x0
 *  01141361   66:8945 d8       mov word ptr ss:[ebp-0x28],ax
 *  01141365   3bfe             cmp edi,esi
 *  01141367   74 10            je short .01141379
 *  01141369   8bc6             mov eax,esi
 *  0114136b   8d4d d8          lea ecx,dword ptr ss:[ebp-0x28]
 *  0114136e   2bc7             sub eax,edi
 *  01141370   d1f8             sar eax,1
 *  01141372   50               push eax
 *  01141373   57               push edi
 *  01141374   e8 b7daf2ff      call .0106ee30
 *  01141379   6a ff            push -0x1
 *  0114137b   6a 00            push 0x0
 *  0114137d   8d45 d8          lea eax,dword ptr ss:[ebp-0x28]
 *  01141380   c645 fc 02       mov byte ptr ss:[ebp-0x4],0x2
 *  01141384   50               push eax
 *  01141385   8d8b a8000000    lea ecx,dword ptr ds:[ebx+0xa8]
 *  0114138b   e8 205cf3ff      call .01076fb0
 *  01141390   837d ec 08       cmp dword ptr ss:[ebp-0x14],0x8
 *  01141394   72 0b            jb short .011413a1
 *  01141396   ff75 d8          push dword ptr ss:[ebp-0x28]
 *  01141399   e8 fccb0e00      call .0122df9a
 *  0114139e   83c4 04          add esp,0x4
 *  011413a1   33c0             xor eax,eax
 *  011413a3   c745 ec 07000000 mov dword ptr ss:[ebp-0x14],0x7
 *  011413aa   c745 e8 00000000 mov dword ptr ss:[ebp-0x18],0x0
 *  011413b1   66:8945 d8       mov word ptr ss:[ebp-0x28],ax
 *  011413b5   c683 f1000000 00 mov byte ptr ds:[ebx+0xf1],0x0
 *  011413bc   8d8d 90feffff    lea ecx,dword ptr ss:[ebp-0x170]
 *  011413c2   c745 fc 03000000 mov dword ptr ss:[ebp-0x4],0x3
 *  011413c9   e8 42bb0800      call .011ccf10
 *  011413ce   8d8d 60fdffff    lea ecx,dword ptr ss:[ebp-0x2a0]
 *  011413d4   c745 fc ffffffff mov dword ptr ss:[ebp-0x4],-0x1
 *  011413db   e8 30bb0800      call .011ccf10
 *  011413e0   8bbd 38fdffff    mov edi,dword ptr ss:[ebp-0x2c8]
 *  011413e6  ^e9 c5fbffff      jmp .01140fb0
 *  011413eb   8b9d 1cfdffff    mov ebx,dword ptr ss:[ebp-0x2e4]
 *  011413f1   85db             test ebx,ebx
 *  011413f3   74 6a            je short .0114145f
 *  011413f5   8b8d 38fdffff    mov ecx,dword ptr ss:[ebp-0x2c8]
 *  011413fb   8379 14 08       cmp dword ptr ds:[ecx+0x14],0x8
 *  011413ff   72 02            jb short .01141403
 *  01141401   8b09             mov ecx,dword ptr ds:[ecx]
 *  01141403   8b85 20fdffff    mov eax,dword ptr ss:[ebp-0x2e0]
 *  01141409   c745 d4 07000000 mov dword ptr ss:[ebp-0x2c],0x7
 *  01141410   c745 d0 00000000 mov dword ptr ss:[ebp-0x30],0x0
 *  01141417   8b00             mov eax,dword ptr ds:[eax]
 *  01141419   8d0441           lea eax,dword ptr ds:[ecx+eax*2]
 *  0114141c   33c9             xor ecx,ecx
 *  0114141e   66:894d c0       mov word ptr ss:[ebp-0x40],cx
 *  01141422   3bf8             cmp edi,eax
 *  01141424   74 0e            je short .01141434
 *  01141426   2bc7             sub eax,edi
 *  01141428   8d4d c0          lea ecx,dword ptr ss:[ebp-0x40]
 *  0114142b   d1f8             sar eax,1
 *  0114142d   50               push eax
 *  0114142e   57               push edi
 *  0114142f   e8 fcd9f2ff      call .0106ee30
 *  01141434   8d45 c0          lea eax,dword ptr ss:[ebp-0x40]
 *  01141437   c745 fc 00000000 mov dword ptr ss:[ebp-0x4],0x0
 *  0114143e   3bd8             cmp ebx,eax
 *  01141440   74 0c            je short .0114144e
 *  01141442   6a ff            push -0x1
 *  01141444   6a 00            push 0x0
 *  01141446   50               push eax
 *  01141447   8bcb             mov ecx,ebx
 *  01141449   e8 c2def2ff      call .0106f310
 *  0114144e   837d d4 08       cmp dword ptr ss:[ebp-0x2c],0x8
 *  01141452   72 0b            jb short .0114145f
 *  01141454   ff75 c0          push dword ptr ss:[ebp-0x40]
 *  01141457   e8 3ecb0e00      call .0122df9a
 *  0114145c   83c4 04          add esp,0x4
 *  0114145f   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  01141462   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  01141469   59               pop ecx
 *  0114146a   5f               pop edi
 *  0114146b   5e               pop esi
 *  0114146c   5b               pop ebx
 *  0114146d   8b4d f0          mov ecx,dword ptr ss:[ebp-0x10]
 *  01141470   33cd             xor ecx,ebp
 *  01141472   e8 14cb0e00      call .0122df8b
 *  01141477   8be5             mov esp,ebp
 *  01141479   5d               pop ebp
 *  0114147a   c2 0800          retn 0x8
 *  0114147d   cc               int3
 *  0114147e   cc               int3
 */
bool InsertSiglus2Hook()
{
  //const BYTE bytes[] = { // size = 14
  //  0x01,0x53, 0x58,                // 0153 58          add dword ptr ds:[ebx+58],edx
  //  0x8b,0x95, 0x34,0xfd,0xff,0xff, // 8b95 34fdffff    mov edx,dword ptr ss:[ebp-2cc]
  //  0x8b,0x43, 0x58,                // 8b43 58          mov eax,dword ptr ds:[ebx+58]
  //  0x3b,0xd7                       // 3bd7             cmp edx,edi ; hook here
  //};
  //enum { cur_ins_size = 2 };
  //enum { hook_offset = sizeof(bytes) - cur_ins_size }; // = 14 - 2  = 12, current inst is the last one

  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr;
  { // type 1
    const BYTE bytes[] = {
      0x3b,0xd7,  // cmp edx,edi ; hook here
      0x75,0x4b   // jnz short
    };
    //enum { hook_offset = 0 };
    addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
    if (addr)
      ConsoleOutput("vnreng:Siglus2: type 1 pattern found");
  }
  if (!addr) {
    const BYTE bytes[] = {
      0x81,0xfe, 0x0c,0x30,0x00,0x00 // 0114124a   81fe 0c300000    cmp esi,0x300c  ; jichi: hook here
    };
    //enum { hook_offset = 0 };
    addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
    if (addr)
      ConsoleOutput("vnreng:Siglus2: type 2 pattern found");
  }

  if (!addr) {
    ConsoleOutput("vnreng:Siglus2: both type1 and type2 patterns not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.off = pusha_esi_off - 4; // -0x20
  hp.type = USING_UNICODE|FIXING_SPLIT; // jichi 6/1/2014: fixing the split value
  hp.length_offset = 1;

  ConsoleOutput("vnreng: INSERT Siglus2");
  NewHook(hp, L"SiglusEngine2");
  //ConsoleOutput("SiglusEngine2");
  return true;
}

static void SpecialHookSiglus1(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  __asm
  {
    mov edx,esp_base
    mov ecx,[edx-0xc]
    mov eax,[ecx+0x14]
    add ecx,4
    cmp eax,0x8
    cmovnb ecx,[ecx]
    mov edx,len
    add eax,eax
    mov [edx],eax
    mov edx,data
    mov [edx],ecx
  }
}

// jichi: 8/17/2013: Change return type to bool
bool InsertSiglus1Hook()
{
  const BYTE bytes[] = {0x33,0xc0,0x8b,0xf9,0x89,0x7c,0x24};
  ULONG range = max(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!addr) { // jichi 8/17/2013: Add "== 0" check to prevent breaking new games
    //ConsoleOutput("Unknown SiglusEngine");
    ConsoleOutput("vnreng:Siglus: pattern not found");
    return false;
  }

  DWORD limit = addr - 0x100;
  while (addr > limit) {
    if (*(WORD*)addr == 0xff6a) {
      HookParam hp = {};
      hp.addr = addr;
      hp.text_fun = SpecialHookSiglus1;
      hp.type = USING_UNICODE;
      ConsoleOutput("vnreng: INSERT Siglus");
      NewHook(hp, L"SiglusEngine");
      //RegisterEngineType(ENGINE_SIGLUS);
      return true;
    }
    addr--;
  }
  ConsoleOutput("vnreng:Siglus: failed");
  return false;
}

} // unnamed namespace

// jichi 8/17/2013: Insert old first. As the pattern could also be found in the old engine.
bool InsertSiglusHook()
{
  if (InsertSiglus1Hook())
    return true;
  bool ok = InsertSiglus2Hook();
  ok = InsertSiglus3Hook() || ok;
  return ok;
}

/********************************************************************************************
MAJIRO hook:
  Game folder contains both data.arc and scenario.arc. arc files is
  quite common seen so we need 2 files to confirm it's MAJIRO engine.

  Font caching issue. Find call to TextOutA and the function entry.

  The original Majiro hook will catch furiga mixed with the text.
  To split them out we need to find a parameter. Seems there's no
  simple way to handle this case.
  At the function entry, EAX seems to point to a structure to describe
  current drawing context. +28 seems to be font size. +48 is negative
  if furigana. I don't know exact meaning of this structure,
  just do memory comparisons and get the value working for current release.

********************************************************************************************/
// jichi 11/28/2014: Disable original Majiro special hook that does not work for new Majiro games, such as: 流され妻
// In the new Majiro engine, arg1 could be zero
#if 0
static void SpecialHookMajiro(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  // jichi 5/12/2014
  // See: http://stackoverflow.com/questions/14210614/bind-function-parameter-to-specific-register
  // x86-64, the first 6 (integral) parameters are passed in the registers %rdi, %rsi, %rdx, %rcx, %r8, and %r9.
  __asm
  {
    mov edx,esp_base
    mov edi,[edx+0xc] ; jichi 5/11/2014: the third function parameter is LPCSTR text
    mov eax,data
    mov [eax],edi
    or ecx,0xffffffff
    xor eax,eax
    repne scasb
    not ecx
    dec ecx
    mov eax,len
    mov [eax],ecx
    mov eax,[edx+4]    ; jichi 5/11/2014: the first function parameter is LPCSTR font name (MS Gothic)
    mov edx,[eax+0x28] ; 0x28 and 0x48 are in the caller of this fuction hook
    mov eax,[eax+0x48] ; *split = ([eax+0x28] & 0xff) | (([eax+0x48] >> 1) & 0xffff00)
    sar eax,0x1f
    mov dh,al
    mov ecx,split
    mov [ecx],edx
  }
}
#endif // 0

/** jichi 12/28/2014: new Majiro hook pattern
 *
 *  Different function starts:
 *
 *  Old Majiro:
 *  enum { sub_esp = 0xec81 }; // caller pattern: sub esp = 0x81,0xec byte
 *
 *  New Majiro since [141128] [アトリエさくら] 流され妻、綾乃の“ネトラレ”報告 体験版
 *  003e9230   55               push ebp
 *  003e9231   8bec             mov ebp,esp
 *  003e9233   83ec 64          sub esp,0x64
 *
 *  Also, function addresses are fixed in old majiro, but floating in new majiro.
 *  In the old Majiro game, caller's address could be used as split.
 *  In the new Majiro game, the hooked function is invoked by the same caller.
 *
 *  Use a split instead.
 *  Sample stack values are as follows.
 *  - Old majiro: arg3 is text, arg1 is font name
 *  - New majiro: arg3 is text, arg4 is font name
 *
 *  Name:
 *  0038f164   003e8163  return to .003e8163 from .003e9230
 *  0038f168   00000000
 *  0038f16c   00000000
 *  0038f170   08b04dbc ; jichi: arg3, text
 *  0038f174   006709f0 ; jichi: arg4, font name
 *  0038f178   006dace8
 *  0038f17c   00000000
 *  0038f180   00000013
 *  0038f184   006fcba8
 *  0038f188   00000078 ; jichi: 0x24, alternative split
 *  0038f18c   00000078
 *  0038f190   00000018
 *  0038f194   00000002
 *  0038f198   08b04dbc
 *  0038f19c   006709f0
 *  0038f1a0   00000000
 *  0038f1a4   00000000
 *  0038f1a8   00000078
 *  0038f1ac   00000018
 *  0038f1b0   08aa0130
 *  0038f1b4   01b6b6c0
 *  0038f1b8   beff26e4
 *  0038f1bc   0038f1fc
 *  0038f1c0   004154af  return to .004154af from .00415400 ; jichi: 0x52, could be used as split
 *  0038f1c4   0000000e
 *  0038f1c8   000001ae
 *  0038f1cc   00000158
 *  0038f1d0   00000023
 *  0038f1d4   beff2680
 *  0038f1d8   0038f208
 *  0038f1dc   003ecfda  return to .003ecfda from .00415400
 *
 *  Scenario:
 *  0038e57c   003e8163  return to .003e8163 from .003e9230
 *  0038e580   00000000
 *  0038e584   00000000
 *  0038e588   0038ee4c  ; jichi: arg3, text
 *  0038e58c   004d5400  .004d5400 ; jichi: arg4, font name
 *  0038e590   006dace8
 *  0038e594   0038ee6d
 *  0038e598   004d7549  .004d7549
 *  0038e59c   00000000
 *  0038e5a0   00000180 ; jichi: 0x24, alternative hook
 *  0038e5a4   00000180
 *  0038e5a8   00000018
 *  0038e5ac   00000002
 *  0038e5b0   0038ee4c
 *  0038e5b4   004d5400  .004d5400
 *  0038e5b8   00000000
 *  0038e5bc   00000000
 *  0038e5c0   00000180
 *  0038e5c4   00000018
 *  0038e5c8   006a0180
 *  0038e5cc   0038e5f8
 *  0038e5d0   0041fc87  return to .0041fc87 from .0041fc99
 *  0038e5d4   0038e5f8
 *  0038e5d8   00418165  return to .00418165 from .0041fc81 ; jichi: used as split
 *  0038e5dc   004d7549  .004d7549
 *  0038e5e0   0038ee6d
 *  0038e5e4   0038e608
 *  0038e5e8   00419555  return to .00419555 from .0041814e
 *  0038e5ec   00000000
 *  0038e5f0   004d7549  .004d7549
 *  0038e5f4   0038ee6d
 *
 *  12/4/2014: Add split for furigana.
 *  Sample game: [141128] [チュアブルソフト] 残念な俺達の青春事情
 *  Following are memory values after arg4 (font name)
 *
 *  Surface: 傍
 *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  ＭＳ Ｐゴシック.
 *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  00EC5420  01 00 00 00 00 00 00 00 1C 00 00 00 0D 00 00 00   ....... .......
 *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -....... .... ; jichi: first byte as split in parenthesis
 *  00EC5440  00(00 00 00)60 F7 3F 00 F0 D8 FF FF 00 00 00 00  ....`・.   ....  ; jichi: first word without first byte as split
 *
 *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ...... ..・..
 *  00EC5460  00 00 00 00 01 00 00 00 00 00 00 00 32 01 00 00  .... .......2 ..
 *  00EC5470  14 00 00 00 01 00 00 00 82 6C 82 72 20 82 6F 83   ... ...ＭＳ Ｐ・ ; MS P Gothic
 *  00EC5480  53                                               S
 *
 *  Furigana: そば
 *  00EC5400  82 6C 82 72 20 83 53 83 56 83 62 83 4E 00 4E 00  ＭＳ ゴシック.N.
 *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  00EC5420  01 00 00 00 00 00 00 00 0E 00 00 00 06 00 00 00   ....... ... ...
 *  00EC5430 (16)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00   ....... ....
 *  00EC5440  00(00 00 00)60 F7 3F 00 F0 D8 FF FF 00 00 00 00  ....`・.   ....
 *
 *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ...... ..・..
 *  00EC5460  00 00 00 00 00 00 00 00 00 00 00 00 32 01 00 00  ............2 ..
 *  00EC5470  14 00 00 00 01 00 00 00 82 6C 82 72 20 82 6F 83   ... ...ＭＳ Ｐ・ ; MS P Gothic
 *  00EC5480  53                                               S
 *
 *  Furigana: そば
 *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  ＭＳ Ｐゴシック.
 *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  00EC5420  01 00 00 00 00 00 00 00 0E 00 00 00 06 00 00 00   ....... ... ...
 *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -....... ....
 *  00EC5440  00(00 00 00)60 F7 3F 00 2B 01 00 00 06 00 00 00  ....`・.+ .. ...
 *
 *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ...... ..・..
 *  00EC5460  00 00 00 00 00 00 00 00 00 00 00 00 32 01 00 00  ............2 ..
 *  00EC5470  14 00 00 00 01 00 00 00 82 6C 82 72 20 82 6F 83   ... ...ＭＳ Ｐ・ ; MS P Gothic
 *  00EC5480  53                                               S
 *
 *  ---- need to split the above and below case
 *
 *  Text: 傍
 *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  ＭＳ Ｐゴシック.
 *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  00EC5420  01 00 00 00 00 00 00 00 1C 00 00 00 0D 00 00 00   ....... .......
 *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -....... .... ; jichi: first byte as split in parenthesis
 *  00EC5440  FF(FF FF FF)60 F7 3F 00 32 01 00 00 14 00 00 00  `・.2 .. ... ; jichi: first word without first byte as split
 *
 *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ...... ..・..
 *  00EC5460  00 00 00 00 01 00 00 00 00 00 00 00 32 01 00 00  .... .......2 ..
 *  00EC5470  14 00 00 00 00 00 00 00 82 6C 82 72 20 82 6F 83   .......ＭＳ Ｐ・ ; MS P Gothic
 *  00EC5480  53                                               S
 *
 *  Text: らには、一人の少女。
 *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  ＭＳ Ｐゴシック.
 *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  00EC5420  01 00 00 00 00 00 00 00 1C 00 00 00 0D 00 00 00   ....... .......
 *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -....... ....
 *  00EC5440  FF(FF FF FF)60 F7 3F 00 4D 01 00 00 14 00 00 00  `・.M .. ...
 *
 *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ...... ..・..
 *  00EC5460  00 00 00 00 01 00 00 00 00 00 00 00 32 01 00 00  .... .......2 ..
 *  00EC5470  14 00 00 00 00 00 00 00 82 6C 82 72 20 82 6F 83   .......ＭＳ Ｐ・ ; MS P Gothic
 *  00EC5480  53                                               S
 */

namespace { // unnamed

// These values are the same as the assembly logic of ITH:
//     ([eax+0x28] & 0xff) | (([eax+0x48] >> 1) & 0xffffff00)
// 0x28 = 10 * 4, 0x48 = 18 / 4
inline DWORD MajiroOldFontSplit(const DWORD *arg) // arg is supposed to be a string, though
{ return (arg[10] & 0xff) | ((arg[18] >> 1) & 0xffffff00); }

// Remove lower bytes use 0xffffff00, which are different for furigana
inline DWORD MajiroNewFontSplit(const DWORD *arg) // arg is supposed to be a string, though
{ return (arg[12] & 0xff) | (arg[16] & 0xffffff00); }

void SpecialHookMajiro(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD arg3 = argof(3, esp_base); // text
  *data = arg3;
  *len = ::strlen((LPCSTR)arg3);
  // IsBadReadPtr is not needed for old Majiro game.
  // I am not sure if it is needed by new Majiro game.
  if (hp->user_value) { // new majiro
    if (DWORD arg4 = argof(4, esp_base)) // old majiro
      *split = MajiroNewFontSplit((LPDWORD)arg4);
    else
      *split = *(DWORD *)(esp_base + 0x5c); // = 4 * 23, caller's caller
  } else if (DWORD arg1 = argof(1, esp_base)) // old majiro
    *split = MajiroOldFontSplit((LPDWORD)arg1);
}
} // unnamed namespace
bool InsertMajiroHook()
{
  // jichi 7/12/2014: Change to accurate memory ranges
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:Majiro: failed to get memory range");
    return false;
  }
  // jichi 4/19/2014: There must be a function in Majiro game which contains 6 TextOutA.
  // That function draws all texts.
  //
  // jichi 11/28/2014: Add new function signature
  const DWORD funcs[] = { // caller patterns
    0xec81,     // sub esp = 0x81,0xec byte old majiro
    0x83ec8b55  // mov ebp,esp, sub esp,*  new majiro
  };
  enum { FunctionCount = sizeof(funcs) / sizeof(*funcs) };
  ULONG addr = MemDbg::findMultiCallerAddress((ULONG)::TextOutA, funcs, FunctionCount, startAddress, stopAddress);
  //ULONG addr = MemDbg::findCallerAddress((ULONG)::TextOutA, 0x83ec8b55, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:Majiro: failed");
    return false;
  }

  bool newMajiro = 0x55 == *(BYTE *)addr;

  HookParam hp = {};
  //hp.off=0xc;
  //hp.split=4;
  //hp.split_ind=0x28;
  //hp.type|=USING_STRING|USING_SPLIT|SPLIT_INDIRECT;
  hp.addr = addr;
  hp.text_fun = SpecialHookMajiro;
  hp.user_value = newMajiro;
  if (newMajiro) {
    hp.type = NO_CONTEXT; // do not use return address for new majiro
    ConsoleOutput("vnreng: INSERT Majiro2");
    NewHook(hp, L"Majiro2");
  } else {
    ConsoleOutput("vnreng: INSERT Majiro");
    NewHook(hp, L"Majiro");
  }
  //RegisterEngineType(ENGINE_MAJIRO);
  return true;
}

/********************************************************************************************
CMVS hook:
  Process name is cmvs.exe or cnvs.exe or cmvs*.exe. Used by PurpleSoftware games.

  Font caching issue. Find call to GetGlyphOutlineA and the function entry.
********************************************************************************************/

namespace { // unnamed

// jichi 3/6/2014: This is the original CMVS hook in ITH
// It does not work for パープルソフトウェア games after しあわせ家族部 (2012)
bool InsertCMVS1Hook()
{
  // jichi 7/12/2014: Change to accurate memory ranges
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:CMVS1: failed to get memory range");
    return false;
  }
  // jichi 4/19/2014: There must be a function in Majiro game which contains 6 TextOutA.
  // That function draws all texts.
  enum { sub_esp = 0xec83 }; // caller pattern: sub esp = 0x83,0xec
  ULONG addr = MemDbg::findCallerAddress((ULONG)::GetGlyphOutlineA, sub_esp, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:CMVS1: failed");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.off = 0x8;
  hp.split = -0x18;
  hp.type = BIG_ENDIAN|USING_SPLIT;
  hp.length_offset = 1 ;

  ConsoleOutput("vnreng: INSERT CMVS1");
  NewHook(hp, L"CMVS");
  //RegisterEngineType(ENGINE_CMVS);
  return true;
}

/**
 *  CMSV
 *  Sample games:
 *  ハピメア: /HAC@48FF3:cmvs32.exe
 *  ハピメアFD: /HB-1C*0@44EE95
 *
 *  Optional: ハピメアFD: /HB-1C*0@44EE95
 *  This hook has issue that the text will be split to a large amount of threads
 *  - length_offset: 1
 *  - off: 4294967264 = 0xffffffe0 = -0x20
 *  - type: 8
 *
 *  ハピメア: /HAC@48FF3:cmvs32.exe
 *  base: 0x400000
 *  - length_offset: 1
 *  - off: 12 = 0xc
 *  - type: 68 = 0x44
 *
 *  00448fee     cc             int3
 *  00448fef     cc             int3
 *  00448ff0  /$ 55             push ebp
 *  00448ff1  |. 8bec           mov ebp,esp
 *  00448ff3  |. 83ec 68        sub esp,0x68 ; jichi: hook here, it is actually  tagTEXTMETRICA
 *  00448ff6  |. 8b01           mov eax,dword ptr ds:[ecx]
 *  00448ff8  |. 56             push esi
 *  00448ff9  |. 33f6           xor esi,esi
 *  00448ffb  |. 33d2           xor edx,edx
 *  00448ffd  |. 57             push edi
 *  00448ffe  |. 894d fc        mov dword ptr ss:[ebp-0x4],ecx
 *  00449001  |. 3bc6           cmp eax,esi
 *  00449003  |. 74 37          je short cmvs32.0044903c
 *  00449005  |> 66:8b78 08     /mov di,word ptr ds:[eax+0x8]
 *  00449009  |. 66:3b7d 0c     |cmp di,word ptr ss:[ebp+0xc]
 *  0044900d  |. 75 0a          |jnz short cmvs32.00449019
 *  0044900f  |. 66:8b7d 10     |mov di,word ptr ss:[ebp+0x10]
 *  00449013  |. 66:3978 0a     |cmp word ptr ds:[eax+0xa],di
 *  00449017  |. 74 0a          |je short cmvs32.00449023
 *  00449019  |> 8bd0           |mov edx,eax
 *  0044901b  |. 8b00           |mov eax,dword ptr ds:[eax]
 *  0044901d  |. 3bc6           |cmp eax,esi
 *  0044901f  |.^75 e4          \jnz short cmvs32.00449005
 *  00449021  |. eb 19          jmp short cmvs32.0044903c
 *  00449023  |> 3bd6           cmp edx,esi
 *  00449025  |. 74 0a          je short cmvs32.00449031
 *  00449027  |. 8b38           mov edi,dword ptr ds:[eax]
 *  00449029  |. 893a           mov dword ptr ds:[edx],edi
 *  0044902b  |. 8b11           mov edx,dword ptr ds:[ecx]
 *  0044902d  |. 8910           mov dword ptr ds:[eax],edx
 *  0044902f  |. 8901           mov dword ptr ds:[ecx],eax
 *  00449031  |> 8b40 04        mov eax,dword ptr ds:[eax+0x4]
 *  00449034  |. 3bc6           cmp eax,esi
 *  00449036  |. 0f85 64010000  jnz cmvs32.004491a0
 *  0044903c  |> 8b55 08        mov edx,dword ptr ss:[ebp+0x8]
 *  0044903f  |. 53             push ebx
 *  00449040  |. 0fb75d 0c      movzx ebx,word ptr ss:[ebp+0xc]
 *  00449044  |. b8 00000100    mov eax,0x10000
 *  00449049  |. 8945 e4        mov dword ptr ss:[ebp-0x1c],eax
 *  0044904c  |. 8945 f0        mov dword ptr ss:[ebp-0x10],eax
 *  0044904f  |. 8d45 e4        lea eax,dword ptr ss:[ebp-0x1c]
 *  00449052  |. 50             push eax                                 ; /pMat2
 *  00449053  |. 56             push esi                                 ; |Buffer
 *  00449054  |. 56             push esi                                 ; |BufSize
 *  00449055  |. 8d4d d0        lea ecx,dword ptr ss:[ebp-0x30]          ; |
 *  00449058  |. 51             push ecx                                 ; |pMetrics
 *  00449059  |. 6a 05          push 0x5                                 ; |Format = GGO_GRAY4_BITMAP
 *  0044905b  |. 53             push ebx                                 ; |Char
 *  0044905c  |. 52             push edx                                 ; |hDC
 *  0044905d  |. 8975 e8        mov dword ptr ss:[ebp-0x18],esi          ; |
 *  00449060  |. 8975 ec        mov dword ptr ss:[ebp-0x14],esi          ; |
 *  00449063  |. ff15 5cf05300  call dword ptr ds:[<&gdi32.getglyphoutli>; \GetGlyphOutlineA
 *  00449069  |. 8b75 10        mov esi,dword ptr ss:[ebp+0x10]
 *  0044906c  |. 0faff6         imul esi,esi
 *  0044906f  |. 8bf8           mov edi,eax
 *  00449071  |. 8d04bd 0000000>lea eax,dword ptr ds:[edi*4]
 *  00449078  |. 3bc6           cmp eax,esi
 *  0044907a  |. 76 02          jbe short cmvs32.0044907e
 *  0044907c  |. 8bf0           mov esi,eax
 *  0044907e  |> 56             push esi                                 ; /Size
 *  0044907f  |. 6a 00          push 0x0                                 ; |Flags = LMEM_FIXED
 *  00449081  |. ff15 34f25300  call dword ptr ds:[<&kernel32.localalloc>; \LocalAlloc
 */
bool InsertCMVS2Hook()
{
  // There are multiple functions satisfy the pattern below.
  // Hook to any one of them is OK.
  const BYTE bytes[] = {  // function begin
    0x55,               // 00448ff0  /$ 55             push ebp
    0x8b,0xec,          // 00448ff1  |. 8bec           mov ebp,esp
    0x83,0xec, 0x68,    // 00448ff3  |. 83ec 68        sub esp,0x68 ; jichi: hook here
    0x8b,0x01,          // 00448ff6  |. 8b01           mov eax,dword ptr ds:[ecx]
    0x56,               // 00448ff8  |. 56             push esi
    0x33,0xf6,          // 00448ff9  |. 33f6           xor esi,esi
    0x33,0xd2,          // 00448ffb  |. 33d2           xor edx,edx
    0x57,               // 00448ffd  |. 57             push edi
    0x89,0x4d, 0xfc,    // 00448ffe  |. 894d fc        mov dword ptr ss:[ebp-0x4],ecx
    0x3b,0xc6,          // 00449001  |. 3bc6           cmp eax,esi
    0x74, 0x37          // 00449003  |. 74 37          je short cmvs32.0044903c
  };
  enum { hook_offset = 3 }; // offset from the beginning of the function
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!addr) {
    ConsoleOutput("vnreng:CMVS2: pattern not found");
    return false;
  }

  //reladdr = 0x48ff0;
  //reladdr = 0x48ff3;
  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = 0xc;
  hp.type = BIG_ENDIAN;
  hp.length_offset = 1 ;

  ConsoleOutput("vnreng: INSERT CMVS2");
  NewHook(hp, L"CMVS2");
  return true;
}

} // unnamed namespace

// jichi 3/7/2014: Insert the old hook first since GetGlyphOutlineA can NOT be found in new games
bool InsertCMVSHook()
{
  // Both CMVS1 and CMVS2 exists in new games.
  // Insert the CMVS2 first. Since CMVS1 could break CMVS2
  // And the CMVS1 games do not have CMVS2 patterns.
  return InsertCMVS2Hook() || InsertCMVS1Hook();
}

namespace { // unnamed rUGP

/********************************************************************************************
rUGP hook:
  Process name is rugp.exe. Used by AGE/GIGA games.

  Font caching issue. Find call to GetGlyphOutlineA and keep stepping out functions.
  After several tries we comes to address in rvmm.dll and everything is catched.
  We see CALL [E*X+0x*] while EBP contains the character data.
  It's not as simple to reverse in rugp at run time as like reallive since rugp dosen't set
  up stack frame. In other words EBP is used for other purpose. We need to find alternative
  approaches.
  The way to the entry of that function gives us clue to find it. There is one CMP EBP,0x8140
  instruction in this function and that's enough! 0x8140 is the start of SHIFT-JIS
  characters. It's determining if ebp contains a SHIFT-JIS character. This function is not likely
  to be used in other ways. We simply search for this instruction and place hook around.
********************************************************************************************/
void SpecialHookRUGP1(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  CC_UNUSED(split);
  DWORD *stack = (DWORD *)esp_base;
  DWORD i,val;
  for (i = 0; i < 4; i++) {
    val = *stack++;
    if ((val>>16) == 0) break;

  }
  if (i < 4) {
    hp->off = i << 2;
    *data = val;
    *len = 2;
    hp->text_fun = nullptr;
    //hp->type &= ~EXTERN_HOOK;
  }
  else
    *len = 0;
}

// jichi 10/1/2013: Change return type to bool
bool InsertRUGP1Hook()
{
  DWORD low, high;
  if (!IthCheckFile(L"rvmm.dll") || !SafeFillRange(L"rvmm.dll", &low, &high)) {
    ConsoleOutput("vnreng:rUGP: rvmm.dll does not exist");
    return false;
  }
  //WCHAR str[0x40];
  LPVOID ch = (LPVOID)0x8140;
  enum { range = 0x20000 };
  DWORD t = SearchPattern(low + range, high - low - range, &ch, 4) + range;
  BYTE *s = (BYTE *)(low + t);
  //if (t) {
  if (t != range) { // jichi 10/1/2013: Changed to compare with 0x20000
    if (*(s - 2) != 0x81)
      return false;
    if (DWORD i = SafeFindEntryAligned((DWORD)s, 0x200)) {
      HookParam hp = {};
      hp.addr = i;
      //hp.off= -8;
      hp.length_offset = 1;
      hp.text_fun = SpecialHookRUGP1;
      hp.type = BIG_ENDIAN;
      ConsoleOutput("vnreng: INSERT rUGP#1");
      NewHook(hp, L"rUGP");
      return true;
    }
  } else {
    t = SearchPattern(low, range, &s, 4);
    if (!t) {
      ConsoleOutput("vnreng:rUGP: pattern not found");
      //ConsoleOutput("Can't find characteristic instruction.");
      return false;
    }

    s = (BYTE *)(low + t);
    for (int i = 0; i < 0x200; i++, s--)
      if (s[0] == 0x90
          && *(DWORD *)(s - 3) == 0x90909090) {
        t = low+ t - i + 1;
        //swprintf(str, L"HookAddr 0x%.8x", t);
        //ConsoleOutput(str);
        HookParam hp = {};
        hp.addr = t;
        hp.off = 0x4;
        hp.length_offset = 1;
        hp.type = BIG_ENDIAN;
        ConsoleOutput("vnreng:INSERT rUGP#2");
        NewHook(hp, L"rUGP");
        //RegisterEngineType(ENGINE_RUGP);
        return true;
      }
  }
  ConsoleOutput("vnreng:rUGP: failed");
  return false;
//rt:
  //ConsoleOutput("Unknown rUGP engine.");
}

/** rUGP2 10/11/2014 jichi
 *
 *  Sample game: マブラヴ オルタネイティヴ トータル・イクリプス
 *  The existing rUGP#1/#2 cannot be identified.
 *  H-codes:
 *  - /HAN-4@1E51D:VM60.DLL
 *    - addr: 124189 = 0x1e51d
 *    - length_offset: 1
 *    - module: 3037492083 = 0xb50c7373
 *    - off: 4294967288 = 0xfffffff8 = -8
 *    - type: 1092 = 0x444
 *  - /HAN-4@1001E51D ( alternative)
 *    - addr: 268559645 = 0x1001e51d
 *    - length_offset: 1
 *    - type: 1028 = 0x404
 *
 *  This function is very long.
 *  1001e4b2  ^e9 c0fcffff      jmp _18.1001e177
 *  1001e4b7   8b45 14          mov eax,dword ptr ss:[ebp+0x14]
 *  1001e4ba   c745 08 08000000 mov dword ptr ss:[ebp+0x8],0x8
 *  1001e4c1   85c0             test eax,eax
 *  1001e4c3   74 3c            je short _18.1001e501
 *  1001e4c5   8378 04 00       cmp dword ptr ds:[eax+0x4],0x0
 *  1001e4c9   7f 36            jg short _18.1001e501
 *  1001e4cb   7c 05            jl short _18.1001e4d2
 *  1001e4cd   8338 00          cmp dword ptr ds:[eax],0x0
 *  1001e4d0   73 2f            jnb short _18.1001e501
 *  1001e4d2   8b4d f0          mov ecx,dword ptr ss:[ebp-0x10]
 *  1001e4d5   8b91 38a20000    mov edx,dword ptr ds:[ecx+0xa238]
 *  1001e4db   8910             mov dword ptr ds:[eax],edx
 *  1001e4dd   8b89 3ca20000    mov ecx,dword ptr ds:[ecx+0xa23c]
 *  1001e4e3   8948 04          mov dword ptr ds:[eax+0x4],ecx
 *  1001e4e6   eb 19            jmp short _18.1001e501
 *  1001e4e8   c745 08 09000000 mov dword ptr ss:[ebp+0x8],0x9
 *  1001e4ef   eb 10            jmp short _18.1001e501
 *  1001e4f1   c745 08 16000000 mov dword ptr ss:[ebp+0x8],0x16
 *  1001e4f8   eb 07            jmp short _18.1001e501
 *  1001e4fa   c745 08 1f000000 mov dword ptr ss:[ebp+0x8],0x1f
 *  1001e501   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  1001e504   8ad0             mov dl,al
 *  1001e506   80f2 20          xor dl,0x20
 *  1001e509   80c2 5f          add dl,0x5f
 *  1001e50c   80fa 3b          cmp dl,0x3b
 *  1001e50f   0f87 80010000    ja _18.1001e695
 *  1001e515   0fb60e           movzx ecx,byte ptr ds:[esi]
 *  1001e518   c1e0 08          shl eax,0x8
 *  1001e51b   0bc1             or eax,ecx
 *  1001e51d   b9 01000000      mov ecx,0x1     ; jichi: hook here
 *  1001e522   03f1             add esi,ecx
 *  1001e524   8945 08          mov dword ptr ss:[ebp+0x8],eax
 *  1001e527   8975 0c          mov dword ptr ss:[ebp+0xc],esi
 *  1001e52a   3d 79810000      cmp eax,0x8179
 *  1001e52f   0f85 9d000000    jnz _18.1001e5d2
 *  1001e535   8b4d f0          mov ecx,dword ptr ss:[ebp-0x10]
 *  1001e538   56               push esi
 *  1001e539   8d55 d0          lea edx,dword ptr ss:[ebp-0x30]
 *  1001e53c   52               push edx
 *  1001e53d   e8 0e0bffff      call _18.1000f050
 *  1001e542   8d4d d0          lea ecx,dword ptr ss:[ebp-0x30]
 *  1001e545   c745 fc 07000000 mov dword ptr ss:[ebp-0x4],0x7
 *  1001e54c   ff15 500a0e10    call dword ptr ds:[0x100e0a50]           ; _19.6a712fa9
 *  1001e552   84c0             test al,al
 *  1001e554   75 67            jnz short _18.1001e5bd
 *  1001e556   8b75 f0          mov esi,dword ptr ss:[ebp-0x10]
 *  1001e559   8d45 d0          lea eax,dword ptr ss:[ebp-0x30]
 *  1001e55c   50               push eax
 *  1001e55d   8bce             mov ecx,esi
 *  1001e55f   c745 e4 01000000 mov dword ptr ss:[ebp-0x1c],0x1
 *  1001e566   c745 e0 00000000 mov dword ptr ss:[ebp-0x20],0x0
 *  1001e56d   e8 5e80ffff      call _18.100165d0
 *  1001e572   0fb7f8           movzx edi,ax
 *  1001e575   57               push edi
 *  1001e576   8bce             mov ecx,esi
 *  1001e578   e8 c380ffff      call _18.10016640
 *  1001e57d   85c0             test eax,eax
 *  1001e57f   74 0d            je short _18.1001e58e
 *  1001e581   f640 38 02       test byte ptr ds:[eax+0x38],0x2
 *  1001e585   74 07            je short _18.1001e58e
 *  1001e587   c745 e0 01000000 mov dword ptr ss:[ebp-0x20],0x1
 *  1001e58e   837d bc 10       cmp dword ptr ss:[ebp-0x44],0x10
 *  1001e592   74 29            je short _18.1001e5bd
 *  1001e594   8b43 28          mov eax,dword ptr ds:[ebx+0x28]
 *  1001e597   85c0             test eax,eax
 */
bool InsertRUGP2Hook()
{
  DWORD low, high;
  if (!IthCheckFile(L"vm60.dll") || !SafeFillRange(L"vm60.dll", &low, &high)) {
    ConsoleOutput("vnreng:rUGP2: vm60.dll does not exist");
    return false;
  }
  const BYTE bytes[] = {
    0x0f,0xb6,0x0e,             // 1001e515   0fb60e           movzx ecx,byte ptr ds:[esi]
    0xc1,0xe0, 0x08,            // 1001e518   c1e0 08          shl eax,0x8
    0x0b,0xc1,                  // 1001e51b   0bc1             or eax,ecx
    0xb9, 0x01,0x00,0x00,0x00,  // 1001e51d   b9 01000000      mov ecx,0x1     ; jichi: hook here
    0x03,0xf1,                  // 1001e522   03f1             add esi,ecx
    0x89,0x45, 0x08,            // 1001e524   8945 08          mov dword ptr ss:[ebp+0x8],eax
    0x89,0x75, 0x0c             // 1001e527   8975 0c          mov dword ptr ss:[ebp+0xc],esi
  };
  enum { hook_offset = 0x1001e51d - 0x1001e515 };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), low, high);
  //ITH_GROWL_DWORD(addr);
  if (!addr) {
    ConsoleOutput("vnreng:rUGP2: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.length_offset = 1;
  hp.off = -8;
  hp.type = NO_CONTEXT|BIG_ENDIAN;
  ConsoleOutput("vnreng: INSERT rUGP2");
  NewHook(hp, L"rUGP2");
  return true;
}

} // unnamed namespace

bool InsertRUGPHook()
{ return InsertRUGP1Hook() || InsertRUGP2Hook(); }

/********************************************************************************************
Lucifen hook:
  Game folder contains *.lpk. Used by Navel games.
  Hook is same to GetTextExtentPoint32A, use ESP to split name.
********************************************************************************************/
void InsertLucifenHook()
{
  // BOOL GetTextExtentPoint32(
  //   _In_   HDC hdc,
  //   _In_   LPCTSTR lpString,
  //   _In_   int c,
  //   _Out_  LPSIZE lpSize
  // );
  HookParam hp = {};
  hp.addr = (DWORD)::GetTextExtentPoint32A;
  hp.off = 0x8; // arg2 lpString
  hp.split = -0x18; // jichi 8/12/2014: = -4 - pusha_esp_off
  hp.length_offset = 3;
  hp.type = USING_STRING|USING_SPLIT;
  ConsoleOutput("vnreng: INSERT Lucifen");
  NewHook(hp, L"Lucifen");
  //RegisterEngineType(ENGINE_LUCIFEN);
}
/********************************************************************************************
System40 hook:
  System40 is a game engine developed by Alicesoft.
  Afaik, there are 2 very different types of System40. Each requires a particular hook.

  Pattern 1: Either SACTDX.dll or SACT2.dll exports SP_TextDraw.
  The first relative call in this function draw text to some surface.
  Text pointer is return by last absolute indirect call before that.
  Split parameter is a little tricky. The first register pushed onto stack at the begining
  usually is used as font size later. According to instruction opcode map, push
  eax -- 50, ecx -- 51, edx -- 52, ebx --53, esp -- 54, ebp -- 55, esi -- 56, edi -- 57
  Split parameter value:
  eax - -8,   ecx - -C,  edx - -10, ebx - -14, esp - -18, ebp - -1C, esi - -20, edi - -24
  Just extract the low 4 bit and shift left 2 bit, then minus by -8,
  will give us the split parameter. e.g. push ebx 53->3 *4->C, -8-C=-14.
  Sometimes if split function is enabled, ITH will split text spoke by different
  character into different thread. Just open hook dialog and uncheck split parameter.
  Then click modify hook.

  Pattern 2: *engine.dll exports SP_SetTextSprite.
  At the entry point, EAX should be a pointer to some structure, character at +0x8.
  Before calling this function, the caller put EAX onto stack, we can also find this
  value on stack. But seems parameter order varies from game release. If a future
  game breaks the EAX rule then we need to disassemble the caller code to determine
  data offset dynamically.
********************************************************************************************/

void InsertAliceHook1(DWORD addr, DWORD module, DWORD limit)
{
  if (!addr) {
    ConsoleOutput("vnreng:AliceHook1: failed");
    return;
  }
  for (DWORD i = addr, s = addr; i < s + 0x100; i++)
    if (*(BYTE *)i == 0xe8) { // Find the first relative call.
      DWORD j = i + 5 + *(DWORD *)(i + 1);
      if (j > module && j < limit) {
        while (true) { // Find the first register push onto stack.
          DWORD c = disasm((BYTE*)s);
          if (c == 1)
            break;
          s += c;
        }
        DWORD c = *(BYTE *)s;
        HookParam hp = {};
        hp.addr = j;
        hp.off = -0x8;
        hp.split = -8 -((c & 0xf) << 2);
        hp.type = USING_STRING|USING_SPLIT;
        //if (s>j) hp.type^=USING_SPLIT;
        ConsoleOutput("vnreng: INSERT AliceHook1");
        NewHook(hp, L"System40");
        //RegisterEngineType(ENGINE_SYS40);
        return;
      }
    }
  ConsoleOutput("vnreng:AliceHook1: failed");
}
void InsertAliceHook2(DWORD addr)
{
  if (!addr) {
    ConsoleOutput("vnreng:AliceHook2: failed");
    return;
  }
  HookParam hp = {};
  hp.addr = addr;
  hp.off = -0x8;
  hp.ind = 0x8;
  hp.length_offset = 1;
  hp.type = DATA_INDIRECT;
  ConsoleOutput("vnreng: INSERT AliceHook2");
  NewHook(hp, L"System40");
  //RegisterEngineType(ENGINE_SYS40);
}

// jichi 8/23/2013 Move here from engine.cc
// Do not work for the latest Alice games
bool InsertAliceHook()
{
  DWORD low, high, addr;
  if (::GetFunctionAddr("SP_TextDraw", &addr, &low, &high, 0) && addr) {
    InsertAliceHook1(addr, low, low + high);
    return true;
  }
  if (::GetFunctionAddr("SP_SetTextSprite", &addr, &low, &high, 0) && addr) {
    InsertAliceHook2(addr);
    return true;
  }
  ConsoleOutput("vnreng:AliceHook: failed");
  return false;
}

/**
 *  jichi 12/26/2013: Rance hook
 *
 *  ランス01 光をもとめて: /HSN4:-14@5506A9
 *  - addr: 5572265 (0x5596a9)
 *  - off: 4
 *  - split: 4294967272 (0xffffffe8 = -0x18)
 *  - type: 1041 (0x411)
 *
 *    the above code has the same pattern except int3.
 *    005506a9  |. e8 f2fb1600    call Rance01.006c02a0 ; hook here
 *    005506ae  |. 83c4 0c        add esp,0xc
 *    005506b1  |. 5f             pop edi
 *    005506b2  |. 5e             pop esi
 *    005506b3  |. b0 01          mov al,0x1
 *    005506b5  |. 5b             pop ebx
 *    005506b6  \. c2 0400        retn 0x4
 *    005506b9     cc             int3
 *
 *  ランス・クエスト: /hsn4:-14@42e08a
 *    0042e08a  |. e8 91ed1f00    call Ranceque.0062ce20 ; hook here
 *    0042e08f  |. 83c4 0c        add esp,0xc
 *    0042e092  |. 5f             pop edi
 *    0042e093  |. 5e             pop esi
 *    0042e094  |. b0 01          mov al,0x1
 *    0042e096  |. 5b             pop ebx
 *    0042e097  \. c2 0400        retn 0x4
 *    0042e09a     cc             int3
 */
bool InsertSystem43Hook()
{
  // 9/25/2014 TODO: I should use matchBytes and replace the part after e8 with XX4
  const BYTE ins[] = {  //   005506a9  |. e8 f2fb1600    call rance01.006c02a0 ; hook here
    0x83,0xc4, 0x0c,    //   005506ae  |. 83c4 0c        add esp,0xc
    0x5f,               //   005506b1  |. 5f             pop edi
    0x5e,               //   005506b2  |. 5e             pop esi
    0xb0, 0x01,         //   005506b3  |. b0 01          mov al,0x1
    0x5b,               //   005506b5  |. 5b             pop ebx
    0xc2, 0x04,0x00,    //   005506b6  \. c2 0400        retn 0x4
    0xcc, 0xcc // patching a few int3 to make sure that this is at the end of the code block
  };
  enum { hook_offset = -5 }; // the function call before the ins
  ULONG addr = module_base_; //- sizeof(ins);
  //addr = 0x5506a9;
  enum { near_call = 0xe8 }; // intra-module function call
  do {
    //addr += sizeof(ins); // so that each time return diff address -- not needed
    ULONG range = min(module_limit_ - addr, MAX_REL_ADDR);
    addr = MemDbg::findBytes(ins, sizeof(ins), addr, addr + range);
    if (!addr) {
      //ITH_MSG(L"failed");
      ConsoleOutput("vnreng:System43: pattern not found");
      return false;
    }
    addr += hook_offset;
  } while(near_call != *(BYTE *)addr); // function call
  //ITH_GROWL_DWORD(addr);

  HookParam hp = {};
  hp.addr = addr;
  hp.off = 4;
  hp.split = -0x18;
  hp.type = NO_CONTEXT|USING_SPLIT|USING_STRING;
  ConsoleOutput("vnreng: INSERT System43");
  NewHook(hp, L"System43");
  return false;
}

/********************************************************************************************
AtelierKaguya hook:
  Game folder contains message.dat. Used by AtelierKaguya games.
  Usually has font caching issue with TextOutA.
  Game engine uses EBP to set up stack frame so we can easily trace back.
  Keep step out until it's in main game module. We notice that either register or
  stack contains string pointer before call instruction. But it's not quite stable.
  In-depth analysis of the called function indicates that there's a loop traverses
  the string one character by one. We can set a hook there.
  This search process is too complex so I just make use of some characteristic
  instruction(add esi,0x40) to locate the right point.
********************************************************************************************/
bool InsertAtelierHook()
{
  //SafeFillRange(process_name_, &base, &size);
  //size=size-base;
  DWORD sig = 0x40c683; // add esi,0x40
  //i=module_base_+SearchPattern(module_base_,module_limit_-module_base_,&sig,3);
  DWORD i;
  for (i = module_base_; i < module_limit_ - 4; i++) {
    sig = *(DWORD *)i & 0xffffff;
    if (0x40c683 == sig)
      break;
  }
  if (i < module_limit_ - 4)
    for (DWORD j=i-0x200; i>j; i--)
      if (*(DWORD *)i == 0xff6acccc) { // find the function entry
        HookParam hp = {};
        hp.addr = i+2;
        hp.off = 8;
        hp.split = -0x18;
        hp.length_offset = 1;
        hp.type = USING_SPLIT;
        ConsoleOutput("vnreng: INSERT Aterlier KAGUYA");
        NewHook(hp, L"Atelier KAGUYA");
        //RegisterEngineType(ENGINE_ATELIER);
        return true;
      }

  ConsoleOutput("vnreng:Aterlier: failed");
  return false;
  //ConsoleOutput("Unknown Atelier KAGUYA engine.");
}
/********************************************************************************************
CIRCUS hook:
  Game folder contains advdata folder. Used by CIRCUS games.
  Usually has font caching issues. But trace back from GetGlyphOutline gives a hook
  which generate repetition.
  If we study circus engine follow Freaka's video, we can easily discover that
  in the game main module there is a static buffer, which is filled by new text before
  it's drawing to screen. By setting a hardware breakpoint there we can locate the
  function filling the buffer. But we don't have to set hardware breakpoint to search
  the hook address if we know some characteristic instruction(cmp al,0x24) around there.
********************************************************************************************/
bool InsertCircusHook1() // jichi 10/2/2013: Change return type to bool
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if (*(WORD *)i == 0xa3c)  //cmp al, 0xA; je
      for (DWORD j = i; j < i + 0x100; j++) {
        BYTE c = *(BYTE *)j;
        if (c == 0xc3)
          break;
        if (c == 0xe8) {
          DWORD k = *(DWORD *)(j+1)+j+5;
          if (k > module_base_ && k < module_limit_) {
            HookParam hp = {};
            hp.addr = k;
            hp.off = 0xc;
            hp.split = -0x18;
            hp.length_offset = 1;
            hp.type = DATA_INDIRECT|USING_SPLIT;
            ConsoleOutput("vnreng: INSERT CIRCUS#1");
            NewHook(hp, L"CIRCUS");
            //RegisterEngineType(ENGINE_CIRCUS);
            return true;
          }
        }
      }
      //break;
  //ConsoleOutput("Unknown CIRCUS engine");
  ConsoleOutput("vnreng:CIRCUS: failed");
  return false;
}

/**
 *  jichi 6/5/2014: Sample function from DC3 at 0x4201d0
 *  004201ce     cc             int3
 *  004201cf     cc             int3
 *  004201d0  /$ 8b4c24 08      mov ecx,dword ptr ss:[esp+0x8]
 *  004201d4  |. 8a01           mov al,byte ptr ds:[ecx]
 *  004201d6  |. 84c0           test al,al
 *  004201d8  |. 74 1c          je short dc3.004201f6
 *  004201da  |. 8b5424 04      mov edx,dword ptr ss:[esp+0x4]
 *  004201de  |. 8bff           mov edi,edi
 *  004201e0  |> 3c 24          /cmp al,0x24
 *  004201e2  |. 75 05          |jnz short dc3.004201e9
 *  004201e4  |. 83c1 02        |add ecx,0x2
 *  004201e7  |. eb 04          |jmp short dc3.004201ed
 *  004201e9  |> 8802           |mov byte ptr ds:[edx],al
 *  004201eb  |. 42             |inc edx
 *  004201ec  |. 41             |inc ecx
 *  004201ed  |> 8a01           |mov al,byte ptr ds:[ecx]
 *  004201ef  |. 84c0           |test al,al
 *  004201f1  |.^75 ed          \jnz short dc3.004201e0
 *  004201f3  |. 8802           mov byte ptr ds:[edx],al
 *  004201f5  |. c3             retn
 *  004201f6  |> 8b4424 04      mov eax,dword ptr ss:[esp+0x4]
 *  004201fa  |. c600 00        mov byte ptr ds:[eax],0x0
 *  004201fd  \. c3             retn
 */
bool InsertCircusHook2() // jichi 10/2/2013: Change return type to bool
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ -4; i++)
    if ((*(DWORD *)i & 0xffffff) == 0x75243c) { // cmp al, 24; je
      if (DWORD j = SafeFindEntryAligned(i, 0x80)) {
        HookParam hp = {};
        hp.addr = j;
        hp.off = 0x8;
        //hp.filter_fun = CharNewLineFilter; // \n\s* is used to remove new line
        hp.type = USING_STRING;
        ConsoleOutput("vnreng: INSERT CIRCUS#2");
        //ITH_GROWL_DWORD(hp.addr); // jichi 6/5/2014: 0x4201d0 for DC3
        NewHook(hp, L"CIRCUS");
        //RegisterEngineType(ENGINE_CIRCUS);
        return true;
      }
      break;
    }
  //ConsoleOutput("Unknown CIRCUS engine.");
  ConsoleOutput("vnreng:CIRCUS: failed");
  return false;
}

/********************************************************************************************
ShinaRio hook:
  Game folder contains rio.ini.
  Problem of default hook GetTextExtentPoint32A is that the text repeat one time.
  But KF just can't resolve the issue. ShinaRio engine always perform integrity check.
  So it's very difficult to insert a hook into the game module. Freaka suggests to refine
  the default hook by adding split parameter on the stack. So far there is 2 different
  version of ShinaRio engine that needs different split parameter. Seems this value is
  fixed to the last stack frame. We just navigate to the entry. There should be a
  sub esp,* instruction. This value plus 4 is just the offset we need.

  New ShinaRio engine (>=2.48) uses different approach.
********************************************************************************************/
namespace { // unnamed
// jichi 3/1/2015: hook for new ShinaRio games
void SpecialHookShina2(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD ptr = *(DWORD*)(esp_base-0x20);
  *split = ptr;
  char* str = *(char**)(ptr+0x160);
  strcpy(text_buffer, str);
  int skip = 0;
  for (str = text_buffer; *str; str++)
    if (str[0] == 0x5f) {
      if (str[1] == 0x72)
        str[0] = str[1]=1;
      else if (str[1] == 0x74) {
        while (str[0] != 0x2f)
          *str++ = 1;
        *str=1;
      }
    }

  for (str = text_buffer; str[skip];)
    if (str[skip] == 1)
      skip++;
    else {
      str[0]=str[skip];
      str++;
    }

  str[0] = 0;
  if (strcmp(text_buffer, text_buffer_prev) == 0)
    *len=0;
  else {
    for (skip = 0; text_buffer[skip]; skip++)
      text_buffer_prev[skip] = text_buffer[skip];
    text_buffer_prev[skip] = 0;
    *data = (DWORD)text_buffer_prev;
    *len = skip;
  }
}

// jichi 3/1/2015: hook for old ShinaRio games
// Used to merge correct text thread.
// 1. Only keep threads with 0 and -1 split
// 2. Skip the thread withb 0 split and with minimum return address
void SpecialHookShina1(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  static DWORD min_retaddr = -1;
  DWORD s = *(DWORD *)(esp_base + hp->split);
  if (s == 0 || (s & 0xffff) == 0xffff) { // only keep threads with 0 and -1 split
    if (s == 0 && retof(esp_base) <= min_retaddr) {
      min_retaddr = retof(esp_base);
      return;
    }
    *split = FIXED_SPLIT_VALUE;
    // Follow the same logic as the hook.
    *data = *(DWORD *)*data; // DATA_INDIRECT
    *len = LeadByteTable[*data & 0xff];
  }
}

// jichi 8/27/2013
// Return ShinaRio version number
// The head of Rio.ini usually looks like:
//     [椎名里緒 v2.49]
// This function will return 49 in the above case.
//
// Games from アトリエさくら do not have Rio.ini, but $procname.ini.
int GetShinaRioVersion()
{
  int ret = 0;
  HANDLE hFile = IthCreateFile(L"RIO.INI", FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
  if (hFile == INVALID_HANDLE_VALUE)  {
    size_t len = ::wcslen(process_name_);
    if (len > 3) {
      wchar_t fname[MAX_PATH];
      ::wcscpy(fname, process_name_);
      fname[len -1] = 'i';
      fname[len -2] = 'n';
      fname[len -3] = 'i';
      hFile = IthCreateFile(fname, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
    }
  }

  if (hFile != INVALID_HANDLE_VALUE)  {
    IO_STATUS_BLOCK ios;
    //char *buffer,*version;//,*ptr;
    enum { BufferSize = 0x40 };
    char buffer[BufferSize];
    NtReadFile(hFile, 0, 0, 0, &ios, buffer, BufferSize, 0, 0);
    NtClose(hFile);
    if (buffer[0] == '[') {
      buffer[0x3f] = 0; // jichi 8/24/2013: prevent strstr from overflow
      if (char *version = ::strstr(buffer, "v2."))
        ::sscanf(version + 3, "%d", &ret); // +3 to skip "v2."
    }
  }
  return ret;
}

} // unnamed namespace

// jichi 8/24/2013: Rewrite ShinaRio logic.
// Test games: ＲＩＮ×ＳＥＮ　(PK), version ShinaRio 2.47
bool InsertShinaHook()
{
  int ver = GetShinaRioVersion();
  if (ver >= 48) { // v2.48, v2.49
    HookParam hp = {};
    hp.addr = (DWORD)::GetTextExtentPoint32A;
    hp.text_fun = SpecialHookShina2;
    hp.type = USING_STRING;
    ConsoleOutput("vnreng: INSERT ShinaRio > 2.47");
    NewHook(hp, L"ShinaRio");
    //RegisterEngineType(ENGINE_SHINA);
    return true;

  } else if (ver > 40) { // <= v2.47. Older games like あやかしびと does not require hcode
    // jichi 3/13/2015: GetGlyphOutlineA is not hooked, which might produce correct text
    // BOOL GetTextExtentPoint32(HDC hdc, LPCTSTR lpString, int c, LPSIZE lpSize);
    enum stack { // current stack
      arg0_retaddr = 0 // pseudo arg
      , arg1_hdc = 4 * 1
      , arg2_lpString = 4 * 2
      , arg3_c = 4 * 3
      , arg4_lpSize = 4 * 4
    };

    HookParam hp = {};
    hp.addr = (DWORD)::GetTextExtentPoint32A;
    hp.off = arg2_lpString; // 0x8
    hp.length_offset = 1;
    hp.type = DATA_INDIRECT|USING_SPLIT;

    enum { sub_esp = 0xec81 }; // jichi: caller pattern: sub esp = 0x81,0xec
    if (DWORD s = Util::FindCallAndEntryBoth((DWORD)GetTextExtentPoint32A, module_limit_ - module_base_, module_base_, sub_esp)) {
      ConsoleOutput("vnreng: INSERT ShinaRio <= 2.47 dynamic split");
      hp.split = *(DWORD *)(s + 2) + 4;
       //RegisterEngineType(ENGINE_SHINA);
      NewHook(hp, L"ShinaRio");

    } else {
      // jichi 3/13/2015: GetTextExtentPoint32A is not statically invoked in ＲＩＮ×ＳＥＮ　(PK)
      // See: http://sakuradite.com/topic/671
      // See: http://www.hongfire.com/forum/showthread.php/36807-AGTH-text-extraction-tool-for-games-translation/page347
      //
      // [Guilty+]Rin x Sen ～Hakudaku Onna Kyoushi to Yaroudomo～: /HB8*0:44@0:GDI32.dll:GetTextExtentPoint32A /Ftext@4339A2:0;choices@4339A2:ffffff
      //
      // addr: 0 , text_fun: 0x0 , function: 135408591 , hook_len: 0 , ind: 0 , length_of
      // fset: 1 , module: 1409538707 , off: 8 , recover_len: 0 , split: 68 , split_ind:
      // 0 , type: 216
      //
      // Message speed needs to be set to something slower then fastest(instant) or text wont show up in agth.
      // Last edited by Freaka; 09-29-2009 at 11:48 AM.

      // Issues:
      // 1. The text speed must NOT to be set to the fastest.
      // 2. There might be a wrong text thread that is almost correct, except that its first character is chopped.
      // Otherwise, the first character will be split in another thread
      ConsoleOutput("vnreng: INSERT ShinaRio <= 2.47 static split");
      hp.split = 0x44;
      //hp.type |= FIXING_SPLIT|NO_CONTEXT; // merge all threads
      //hp.text_fun = SpecialHookShina1;
      NewHook(hp, L"ShinaRio2"); // jichi: mark as ShinaRio2 so that VNR is able to warn user about the text speed issue
    }
    return true;
  }
  ConsoleOutput("vnreng:ShinaRio: unknown version");
  return false;
}

bool InsertWaffleDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != ::GetTextExtentPoint32A)
    return false;

  DWORD handler;
  __asm
  {
    mov eax,fs:[0]
    mov eax,[eax]
    mov eax,[eax]
    mov eax,[eax]
    mov eax,[eax]
    mov eax,[eax]
    mov ecx, [eax + 4]
    mov handler, ecx
  }

  union {
    DWORD i;
    BYTE *ib;
    DWORD *id;
  };
  // jichi 9/30/2013: Fix the bug in ITH logic where j is uninitialized
  for (i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if (*id == handler && *(ib - 1) == 0x68)
      if (DWORD t = SafeFindEntryAligned(i, 0x40)) {
        HookParam hp = {};
        hp.addr = t;
        hp.off = 8;
        hp.ind = 4;
        hp.length_offset = 1;
        hp.type = DATA_INDIRECT;
        ConsoleOutput("vnreng: INSERT Dynamic Waffle");
        NewHook(hp, L"Waffle");
        return true;
      }
  ConsoleOutput("vnreng:DynamicWaffle: failed");
  //ConsoleOutput("Unknown waffle engine.");
  return true; // jichi 12/25/2013: return true
}
//  DWORD retn,limit,str;
//  WORD ch;
//  NTSTATUS status;
//  MEMORY_BASIC_INFORMATION info;
//  str = *(DWORD*)(stack+0xC);
//  ch = *(WORD*)str;
//  if (ch<0x100) return false;
//  limit = (stack | 0xFFFF) + 1;
//  __asm int 3
//  for (stack += 0x10; stack < limit; stack += 4)
//  {
//    str = *(DWORD*)stack;
//    if ((str >> 16) != (stack >> 16))
//    {
//      status = NtQueryVirtualMemory(NtCurrentProcess(),(PVOID)str,MemoryBasicInformation,&info,sizeof(info),0);
//      if (!NT_SUCCESS(status) || info.Protect & PAGE_NOACCESS) continue; //Accessible
//    }
//    if (*(WORD*)(str + 4) == ch) break;
//  }
//  if (stack < limit)
//  {
//    for (limit = stack + 0x100; stack < limit ; stack += 4)
//    if (*(DWORD*)stack == -1)
//    {
//      retn = *(DWORD*)(stack + 4);
//      if (retn > module_base_ && retn < module_limit_)
//      {
//        HookParam hp = {};
//        hp.addr = retn + *(DWORD*)(retn - 4);
//        hp.length_offset = 1;
//        hp.off = -0x20;
//        hp.ind = 4;
//        //hp.split = 0x1E8;
//        hp.type = DATA_INDIRECT;
//        NewHook(hp, L"WAFFLE");
//        //RegisterEngineType(ENGINE_WAFFLE);
//        return true;
//      }
//
//    }
//
//  }

void InsertWaffleHook()
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == 0xac68) {
      HookParam hp = {};
      hp.addr = i;
      hp.length_offset = 1;
      hp.off = -0x20;
      hp.ind = 4;
      hp.split = 0x1e8;
      hp.type = DATA_INDIRECT|USING_SPLIT;
      ConsoleOutput("vnreng: INSERT WAFFLE");
      NewHook(hp, L"WAFFLE");
      return;
    }
  //ConsoleOutput("Probably Waffle. Wait for text.");
  trigger_fun_ = InsertWaffleDynamicHook;
  SwitchTrigger(true);
  //ConsoleOutput("vnreng:WAFFLE: failed");
}

void InsertTinkerBellHook()
{
  //DWORD s1,s2,i;
  //DWORD ch=0x8141;
  DWORD i;
  WORD count;
  count = 0;
  HookParam hp = {};
  hp.length_offset = 1;
  hp.type = BIG_ENDIAN|NO_CONTEXT;
  for (i = module_base_; i< module_limit_ - 4; i++) {
    if (*(DWORD*)i == 0x8141) {
      BYTE t = *(BYTE*)(i - 1);
      if (t == 0x3d || t == 0x2d) {
        hp.off = -0x8;
        hp.addr = i - 1;
      } else if (*(BYTE*)(i-2) == 0x81) {
        t &= 0xf8;
        if (t == 0xf8 || t == 0xe8) {
          hp.off = -8 - ((*(BYTE*)(i-1) & 7) << 2);
          hp.addr = i - 2;
        }
      }
      if (hp.addr) {
        WCHAR hook_name[0x20];
        memcpy(hook_name, L"TinkerBell", 0x14);
        hook_name[0xa] = L'0' + count;
        hook_name[0xb] = 0;
        ConsoleOutput("vnreng:INSERT TinkerBell");
        NewHook(hp, hook_name);
        count++;
        hp.addr = 0;
      }
    }
  }
  ConsoleOutput("vnreng:TinkerBell: failed");
}

//  s1=SearchPattern(module_base_,module_limit_-module_base_-4,&ch,4);
//  if (s1)
//  {
//    for (i=s1;i>s1-0x400;i--)
//    {
//      if (*(WORD*)(module_base_+i)==0xec83)
//      {
//        hp.addr=module_base_+i;
//        NewHook(hp, L"C.System");
//        break;
//      }
//    }
//  }
//  s2=s1+SearchPattern(module_base_+s1+4,module_limit_-s1-8,&ch,4);
//  if (s2)
//  {
//    for (i=s2;i>s2-0x400;i--)
//    {
//      if (*(WORD*)(module_base_+i)==0xec83)
//      {
//        hp.addr=module_base_+i;
//        NewHook(hp, L"TinkerBell");
//        break;
//      }
//    }
//  }
//  //if (count)
  //RegisterEngineType(ENGINE_TINKER);

// jichi 3/19/2014: Insert both hooks
//void InsertLuneHook()
bool InsertMBLHook()
{
  enum : DWORD { fun = 0xec8b55 }; // jichi 10/20/2014: mov ebp,esp, sub esp,*
  bool ret = false;
  if (DWORD c = Util::FindCallOrJmpAbs((DWORD)::ExtTextOutA, module_limit_ - module_base_, module_base_, true))
    if (DWORD addr = Util::FindCallAndEntryRel(c, module_limit_ - module_base_, module_base_, fun)) {
      HookParam hp = {};
      hp.addr = addr;
      hp.off = 4;
      hp.type = USING_STRING;
      ConsoleOutput("vnreng:INSERT MBL-Furigana");
      NewHook(hp, L"MBL-Furigana");
      ret = true;
    }
  if (DWORD c = Util::FindCallOrJmpAbs((DWORD)::GetGlyphOutlineA, module_limit_ - module_base_, module_base_, true))
    if (DWORD addr = Util::FindCallAndEntryRel(c, module_limit_ - module_base_, module_base_, fun)) {
      HookParam hp = {};
      hp.addr = addr;
      hp.off = 4;
      hp.split = -0x18;
      hp.length_offset = 1;
      hp.type = BIG_ENDIAN|USING_SPLIT;
      ConsoleOutput("vnreng:INSERT MBL");
      NewHook(hp, L"MBL");
      ret = true;
    }
  if (!ret)
    ConsoleOutput("vnreng:MBL: failed");
  return ret;
}

/** jichi 7/26/2014: E.A.G.L.S engine for TechArts games (SQUEEZ, May-Be Soft)
 *  Sample games: [May-Be Soft] ちぇ～んじ！
 *  Should also work for SQUEEZ's 孕ませシリーズ
 *
 *  Two functions  calls to GetGlyphOutlineA are responsible for painting.
 *  - 0x4094ef
 *  - 0x409e35
 *  However, by default, one of the thread is like: scenario namename scenario
 *  The other thread have infinite loop.
 */
bool InsertEaglsHook()
{
  // DWORD GetGlyphOutline(HDC hdc, UINT uChar,  UINT uFormat, LPGLYPHMETRICS lpgm, DWORD cbBuffer, LPVOID lpvBuffer, const MAT2 *lpmat2);
  enum stack { // current stack
    arg0_retaddr = 0 // pseudo arg
    , arg1_hdc = 4 * 1
    , arg2_uChar = 4 * 2
    , arg3_uFormat = 4 * 3
    , arg4_lpgm = 4 * 4
    , arg5_cbBuffer = 4 * 5
    , arg6_lpvBuffer = 4 * 6
    , arg7_lpmat2 = 4 * 7
  };

  // Modify the split for GetGlyphOutlineA
  HookParam hp = {};
  hp.addr = (DWORD)::GetGlyphOutlineA;
  hp.type = BIG_ENDIAN|USING_SPLIT; // the only difference is the split value
  hp.off = arg2_uChar;
  hp.split = arg4_lpgm;
  //hp.split = arg7_lpmat2;
  hp.length_offset = 1;
  ConsoleOutput("vnreng:INSERT EAGLS");
  NewHook(hp, L"EAGLS");
  return true;
}

/********************************************************************************************
YU-RIS hook:
  Becomes common recently. I first encounter this game in Whirlpool games.
  Problem is name is repeated multiple times.
  Step out of function call to TextOuA, just before call to this function,
  there should be a piece of code to calculate the length of the name.
  This length is 2 for single character name and text,
  For a usual name this value is greater than 2.
********************************************************************************************/

//bool InsertWhirlpoolHook() // jichi: 12/27/2014: Renamed to YU-RIS
static bool InsertYuris1Hook()
{
  //IthBreak();
  DWORD entry = Util::FindCallAndEntryBoth((DWORD)TextOutA, module_limit_ - module_base_, module_base_, 0xec83);
  //ITH_GROWL_DWORD(entry);
  if (!entry) {
    ConsoleOutput("vnreng:YU-RIS: function entry does not exist");
    return false;
  }
  entry = Util::FindCallAndEntryRel(entry - 4, module_limit_ - module_base_, module_base_, 0xec83);
  //ITH_GROWL_DWORD(entry);
  if (!entry) {
    ConsoleOutput("vnreng:YU-RIS: function entry does not exist");
    return false;
  }
  entry = Util::FindCallOrJmpRel(entry - 4,module_limit_ - module_base_ - 0x10000, module_base_ + 0x10000, false);
  DWORD i,
        t = 0;
  //ITH_GROWL_DWORD(entry);
  ITH_TRY { // jichi 12/27/2014
    for (i = entry - 4; i > entry - 0x100; i--)
      if (::IsBadReadPtr((LPCVOID)i, 4)) { // jichi 12/27/2014: might raise in new YU-RIS, 4 = sizeof(DWORD)
        ConsoleOutput("vnreng:YU-RIS: do not have read permission");
        return false;
      } else if (*(WORD *)i == 0xc085) {
        t = *(WORD *)(i + 2);
        if ((t & 0xff) == 0x76) {
          t = 4;
          break;
        } else if ((t & 0xffff) == 0x860f) {
          t = 8;
          break;
        }
      }

  } ITH_EXCEPT {
    ConsoleOutput("vnreng:YU-RIS: illegal access exception");
    return false;
  }
  if (i == entry - 0x100) {
    ConsoleOutput("vnreng:YU-RIS: pattern not exist");
    return false;
  }
  //ITH_GROWL_DWORD2(i,t);
  HookParam hp = {};
  hp.addr = i + t;
  hp.off = -0x24;
  hp.split = -0x8;
  hp.type = USING_STRING|USING_SPLIT;
  ConsoleOutput("vnreng: INSERT YU-RIS");
  //ITH_GROWL_DWORD(hp.addr);
  NewHook(hp, L"YU-RIS");
  //RegisterEngineType(ENGINE_WHIRLPOOL);
  return true;
}

/** jichi 12/27/2014
 *
 *  Sample game: [Whirlpool] [150217] 鯨神のティアスティラ
 *  Call site of TextOutA.
 *  00441811   90               nop
 *  00441812   90               nop
 *  00441813   90               nop
 *  00441814   8b4424 04        mov eax,dword ptr ss:[esp+0x4]
 *  00441818   8b5424 08        mov edx,dword ptr ss:[esp+0x8]
 *  0044181c   8b4c24 0c        mov ecx,dword ptr ss:[esp+0xc]
 *  00441820   57               push edi
 *  00441821   56               push esi
 *  00441822   55               push ebp
 *  00441823   53               push ebx
 *  00441824   83ec 50          sub esp,0x50
 *  00441827   8bf9             mov edi,ecx
 *  00441829   897c24 1c        mov dword ptr ss:[esp+0x1c],edi
 *  0044182d   8bda             mov ebx,edx
 *  0044182f   8be8             mov ebp,eax
 *  00441831   8b349d 603f7b00  mov esi,dword ptr ds:[ebx*4+0x7b3f60]
 *  00441838   807c24 74 01     cmp byte ptr ss:[esp+0x74],0x1
 *  0044183d   b9 00000000      mov ecx,0x0
 *  00441842   0f94c1           sete cl
 *  00441845   8d041b           lea eax,dword ptr ds:[ebx+ebx]
 *  00441848   03c3             add eax,ebx
 *  0044184a   0fafc1           imul eax,ecx
 *  0044184d   03c3             add eax,ebx
 *  0044184f   894424 0c        mov dword ptr ss:[esp+0xc],eax
 *  00441853   897424 10        mov dword ptr ss:[esp+0x10],esi
 *  00441857   8bc3             mov eax,ebx
 *  00441859   8bd7             mov edx,edi
 *  0044185b   0fbe4c24 70      movsx ecx,byte ptr ss:[esp+0x70]
 *  00441860   e8 0c030000      call .00441b71
 *  00441865   0fbec8           movsx ecx,al
 *  00441868   83f9 ff          cmp ecx,-0x1
 *  0044186b   0f84 db020000    je .00441b4c
 *  00441871   8bce             mov ecx,esi
 *  00441873   0fafc9           imul ecx,ecx
 *  00441876   a1 64365d00      mov eax,dword ptr ds:[0x5d3664]
 *  0044187b   8bf9             mov edi,ecx
 *  0044187d   c1ff 02          sar edi,0x2
 *  00441880   c1ef 1d          shr edi,0x1d
 *  00441883   03f9             add edi,ecx
 *  00441885   c1ff 03          sar edi,0x3
 *  00441888   68 ff000000      push 0xff
 *  0044188d   57               push edi
 *  0044188e   ff3485 70b48300  push dword ptr ds:[eax*4+0x83b470]
 *  00441895   ff15 a4355d00    call dword ptr ds:[0x5d35a4]             ; .00401c88
 *  0044189b   83c4 0c          add esp,0xc
 *  0044189e   8b0d 64365d00    mov ecx,dword ptr ds:[0x5d3664]
 *  004418a4   ff348d b4b48300  push dword ptr ds:[ecx*4+0x83b4b4]
 *  004418ab   ff348d d4b48300  push dword ptr ds:[ecx*4+0x83b4d4]
 *  004418b2   ff15 54e05800    call dword ptr ds:[0x58e054]             ; gdi32.selectobject
 *  004418b8   a3 b0b48300      mov dword ptr ds:[0x83b4b0],eax
 *  004418bd   8b0d 64365d00    mov ecx,dword ptr ds:[0x5d3664]
 *  004418c3   ff348d 30b48300  push dword ptr ds:[ecx*4+0x83b430]
 *  004418ca   ff348d d4b48300  push dword ptr ds:[ecx*4+0x83b4d4]
 *  004418d1   ff15 54e05800    call dword ptr ds:[0x58e054]             ; gdi32.selectobject
 *  004418d7   a3 2cb48300      mov dword ptr ds:[0x83b42c],eax
 *  004418dc   8b3d 64365d00    mov edi,dword ptr ds:[0x5d3664]
 *  004418e2   33c9             xor ecx,ecx
 *  004418e4   880cbd f5b48300  mov byte ptr ds:[edi*4+0x83b4f5],cl
 *  004418eb   880cbd f6b48300  mov byte ptr ds:[edi*4+0x83b4f6],cl
 *  004418f2   0fb64d 00        movzx ecx,byte ptr ss:[ebp]
 *  004418f6   0fb689 a0645b00  movzx ecx,byte ptr ds:[ecx+0x5b64a0]
 *  004418fd   41               inc ecx
 *  004418fe   0fbec9           movsx ecx,cl
 *  00441901   51               push ecx
 *  00441902   55               push ebp
 *  00441903   33c9             xor ecx,ecx
 *  00441905   51               push ecx
 *  00441906   51               push ecx
 *  00441907   ff34bd d4b48300  push dword ptr ds:[edi*4+0x83b4d4]
 *  0044190e   ff15 74e05800    call dword ptr ds:[0x58e074]             ; gdi32.textouta, jichi: TextOutA here
 *  00441914   0fb67d 00        movzx edi,byte ptr ss:[ebp]
 *  00441918   0fb68f a0645b00  movzx ecx,byte ptr ds:[edi+0x5b64a0]
 *  0044191f   41               inc ecx
 *  00441920   0fbef9           movsx edi,cl
 *  00441923   8b0d 64365d00    mov ecx,dword ptr ds:[0x5d3664]
 *  00441929   03c9             add ecx,ecx
 *  0044192b   8d8c09 f4b48300  lea ecx,dword ptr ds:[ecx+ecx+0x83b4f4]
 *
 *  Runtime stack: The first dword after arguments on the stack seems to be good split value.
 */
static bool InsertYuris2Hook()
{
  ULONG addr = MemDbg::findCallAddress((ULONG)::TextOutA, module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:YU-RIS2: failed");
    return false;
  }

  // BOOL TextOut(
  //   _In_  HDC hdc,
  //   _In_  int nXStart,
  //   _In_  int nYStart,
  //   _In_  LPCTSTR lpString,
  //   _In_  int cchString
  // );
  enum stack { // current stack
    arg1_hdc = 4 * 0 // starting from 0 before function call
    , arg2_nXStart = 4 * 1
    , arg3_nYStart = 4 * 2
    , arg4_lpString = 4 * 3
    , arg5_cchString = 4 * 4
    , arg6_split = 4 * 5 // dummy argument
  };

  HookParam hp = {};
  hp.addr = addr;
  hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT; // disable context that will cause thread split
  hp.off = arg4_lpString;
  hp.split = arg6_split;

  ConsoleOutput("vnreng: INSERT YU-RIS 2");
  NewHook(hp, L"YU-RIS2");
  return true;
}

bool InsertYurisHook()
{ return InsertYuris1Hook() || InsertYuris2Hook(); }

bool InsertCotophaHook()
{
  // jichi 7/12/2014: Change to accurate memory ranges
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:Cotopha: failed to get memory range");
    return false;
  }
  enum : DWORD { ins = 0xec8b55 }; // mov ebp,esp, sub esp,*  ; jichi 7/12/2014
  ULONG addr = MemDbg::findCallerAddress((ULONG)::GetTextMetricsA, ins, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:Cotopha: pattern not exist");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr;
  hp.off = 4;
  hp.split = -0x1c;
  hp.type = USING_UNICODE|USING_SPLIT|USING_STRING;
  ConsoleOutput("vnreng: INSERT Cotopha");
  NewHook(hp, L"Cotopha");
  //RegisterEngineType(ENGINE_COTOPHA);
  return true;
}

// jichi 5/10/2014
// See also: http://bbs.sumisora.org/read.php?tid=11044704&fpage=2
//
// Old engine:  グリザイアの迷宮
// 0053cc4e   cc               int3
// 0053cc4f   cc               int3
// 0053cc50   6a ff            push -0x1    ; jichi: hook here
// 0053cc52   68 6b486000      push .0060486b
// 0053cc57   64:a1 00000000   mov eax,dword ptr fs:[0]
// 0053cc5d   50               push eax
// 0053cc5e   81ec 24020000    sub esp,0x224
// 0053cc64   a1 f8647600      mov eax,dword ptr ds:[0x7664f8]
// 0053cc69   33c4             xor eax,esp
// 0053cc6b   898424 20020000  mov dword ptr ss:[esp+0x220],eax
// 0053cc72   53               push ebx
// 0053cc73   55               push ebp
// 0053cc74   56               push esi
// 0053cc75   57               push edi
//
// Stack:
// 0544e974   0053d593  return to .0053d593 from .0053cc50
// 0544e978   045cc820
// 0544e97c   00008dc5  : jichi: text
// 0544e980   00000016
// 0544e984   0452f2e4
// 0544e988   00000000
// 0544e98c   00000001
// 0544e990   0544ea94
// 0544e994   04513840
// 0544e998   0452f2b8
// 0544e99c   04577638
// 0544e9a0   04620450
// 0544e9a4   00000080
// 0544e9a8   00000080
// 0544e9ac   004914f3  return to .004914f3 from .0055c692
//
// Registers:
// edx 0
// ebx 00000016
//
//
// New engine: イノセントガール
// Stack:
// 051ae508   0054e9d1  return to .0054e9d1 from .0054e310
// 051ae50c   04361650
// 051ae510   00008ca9  ; jichi: text
// 051ae514   0000001a
// 051ae518   04343864
// 051ae51c   00000000
// 051ae520   00000001
// 051ae524   051ae62c
// 051ae528   041edc20
// 051ae52c   04343830
// 051ae530   0434a8b0
// 051ae534   0434a7f0
// 051ae538   00000080
// 051ae53c   00000080
// 051ae540   3f560000
// 051ae544   437f8000
// 051ae548   4433e000
// 051ae54c   16f60c00
// 051ae550   051ae650
// 051ae554   042c4c20
// 051ae558   0000002c
// 051ae55c   00439bc5  return to .00439bc5 from .0043af60
//
// Registers & stack:
// Scenario:
// eax 04361650
// ecx 04357640
// edx 04343864
// ebx 0000001a
// esp 051ae508
// ebp 00008169
// esi 04357640
// edi 051ae62c
// eip 0054e310 .0054e310
//
// 051ae508   0054e9d1  return to .0054e9d1 from .0054e310
// 051ae50c   04361650
// 051ae510   00008169
// 051ae514   0000001a
// 051ae518   04343864
// 051ae51c   00000000
// 051ae520   00000001
// 051ae524   051ae62c
// 051ae528   041edc20
// 051ae52c   04343830
// 051ae530   0434a8b0
// 051ae534   0434a7f0
// 051ae538   00000080
// 051ae53c   00000080
// 051ae540   3f560000
// 051ae544   437f8000
// 051ae548   4433e000
// 051ae54c   16f60c00
// 051ae550   051ae650
// 051ae554   042c4c20
// 051ae558   0000002c
//
// Name:
//
// eax 04362430
// ecx 17025230
// edx 0430b6e4
// ebx 0000001a
// esp 051ae508
// ebp 00008179
// esi 17025230
// edi 051ae62c
// eip 0054e310 .0054e310
//
// 051ae508   0054e9d1  return to .0054e9d1 from .0054e310
// 051ae50c   04362430
// 051ae510   00008179
// 051ae514   0000001a
// 051ae518   0430b6e4
// 051ae51c   00000000
// 051ae520   00000001
// 051ae524   051ae62c
// 051ae528   041edae0
// 051ae52c   0430b6b0
// 051ae530   0434a790
// 051ae534   0434a910
// 051ae538   00000080
// 051ae53c   00000080
// 051ae540   3efa0000
// 051ae544   4483f000
// 051ae548   44322000
// 051ae54c   16f60aa0
// 051ae550   051ae650
// 051ae554   042c4c20
// 051ae558   0000002c

static void SpecialHookCatSystem3(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  //DWORD ch = *data = *(DWORD *)(esp_base + hp->off); // arg2
  DWORD ch = *data = argof(2, esp_base);
  *len = LeadByteTable[(ch >> 8) & 0xff];  // BIG_ENDIAN
  *split = regof(edx, esp_base) >> 16;
}

bool InsertCatSystemHook()
{
  //DWORD search=0x95EB60F;
  //DWORD j,i=SearchPattern(module_base_,module_limit_-module_base_,&search,4);
  //if (i==0) return;
  //i+=module_base_;
  //for (j=i-0x100;i>j;i--)
  //  if (*(DWORD*)i==0xcccccccc) break;
  //if (i==j) return;
  //hp.addr=i+4;
  //hp.off=-0x8;
  //hp.ind=4;
  //hp.split=4;
  //hp.split_ind=0x18;
  //hp.type =BIG_ENDIAN|DATA_INDIRECT|USING_SPLIT|SPLIT_INDIRECT;
  //hp.length_offset=1;

  // jichi 7/12/2014: Change to accurate memory ranges
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:CatSystem2: failed to get memory range");
    return false;
  }
  enum { beg = 0xff6acccc }; // jichi 7/12/2014: beginning of the function
  enum { hook_offset = 2 }; // skip two leading 0xcc
  ULONG addr = MemDbg::findCallerAddress((ULONG)::GetTextMetricsA, beg, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:CatSystem2: pattern not exist");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset; // skip 1 push?
  hp.off = 4 * 2; // text character is in arg2
  hp.length_offset = 1; // only 1 character
  hp.type = BIG_ENDIAN|USING_SPLIT;

  // jichi 12/23/2014: Modify split for new catsystem
  bool newEngine = IthCheckFile(L"cs2conf.dll");
  if (newEngine) {
    hp.text_fun = SpecialHookCatSystem3;
    NewHook(hp, L"CatSystem3");
    ConsoleOutput("vnreng: INSERT CatSystem3");
  } else {
    hp.split = pusha_edx_off - 4; // -0x10
    NewHook(hp, L"CatSystem2");
    ConsoleOutput("vnreng: INSERT CatSystem2");
  }
  //RegisterEngineType(ENGINE_CATSYSTEM);
  return true;
}

bool InsertNitroPlusHook()
{
  const BYTE bytes[] = {0xb0, 0x74, 0x53};
  DWORD addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:NitroPlus: pattern not exist");
    return false;
  }
  enum : WORD { sub_esp = 0xec83 }; // caller pattern: sub esp = 0x83,0xec
  BYTE b = *(BYTE *)(addr + 3) & 3;
  while (*(WORD *)addr != sub_esp)
    addr--;
  HookParam hp = {};
  hp.addr = addr;
  hp.off = -0x14+ (b << 2);
  hp.length_offset = 1;
  hp.type = BIG_ENDIAN;
  ConsoleOutput("vnreng: INSERT NitroPlus");
  NewHook(hp, L"NitroPlus");
  //RegisterEngineType(ENGINE_NITROPLUS);
  return true;
}

bool InsertRetouchHook()
{
  DWORD addr;
  if (GetFunctionAddr("?printSub@RetouchPrintManager@@AAE_NPBDAAVUxPrintData@@K@Z", &addr, nullptr, nullptr, nullptr) ||
      GetFunctionAddr("?printSub@RetouchPrintManager@@AAEXPBDKAAH1@Z", &addr, nullptr, nullptr, nullptr)) {
    HookParam hp = {};
    hp.addr = addr;
    hp.off = 4;
    hp.type = USING_STRING;
    ConsoleOutput("vnreng: INSERT RetouchSystem");
    NewHook(hp, L"RetouchSystem");
    return true;
  }
  ConsoleOutput("vnreng:RetouchSystem: failed");
  //ConsoleOutput("Unknown RetouchSystem engine.");
  return false;
}

namespace { // unnamed Malie
/********************************************************************************************
Malie hook:
  Process name is malie.exe.
  This is the most complicate code I have made. Malie engine store text string in
  linked list. We need to insert a hook to where it travels the list. At that point
  EBX should point to a structure. We can find character at -8 and font size at +10.
  Also need to enable ITH suppress function.
********************************************************************************************/
bool InsertMalieHook1()
{
  const DWORD sig1 = 0x05e3c1;
  enum { sig1_size = 3 };
  DWORD i = SearchPattern(module_base_, module_limit_ - module_base_, &sig1, sig1_size);
  if (!i) {
    ConsoleOutput("vnreng:MalieHook1: pattern i not exist");
    return false;
  }

  const WORD sig2 = 0xc383;
  enum { sig2_size = 2 };
  DWORD j = i + module_base_ + sig1_size;
  i = SearchPattern(j, module_limit_ - j, &sig2, sig2_size);
  //if (!j)
  if (!i) { // jichi 8/19/2013: Change the condition fro J to I
    ConsoleOutput("vnreng:MalieHook1: pattern j not exist");
    return false;
  }
  HookParam hp = {};
  hp.addr = j + i;
  hp.off = -0x14;
  hp.ind = -0x8;
  hp.split = -0x14;
  hp.split_ind = 0x10;
  hp.length_offset = 1;
  hp.type = USING_UNICODE|USING_SPLIT|DATA_INDIRECT|SPLIT_INDIRECT;
  ConsoleOutput("vnreng: INSERT MalieHook1");
  NewHook(hp, L"Malie");
  //RegisterEngineType(ENGINE_MALIE);
  return true;
}

DWORD malie_furi_flag_; // jichi 8/20/2013: Make it global so that it can be reset
void SpecialHookMalie(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD ch = *(DWORD *)(esp_base - 0x8) & 0xffff,
        ptr = *(DWORD *)(esp_base - 0x24);
  *data = ch;
  *len = 2;
  if (malie_furi_flag_) {
    DWORD index = *(DWORD *)(esp_base - 0x10);
    if (*(WORD *)(ptr + index * 2 - 2) < 0xa)
      malie_furi_flag_ = 0;
  }
  else if (ch == 0xa) {
    malie_furi_flag_ = 1;
    len = 0;
  }
  *split = malie_furi_flag_;
}

bool InsertMalieHook2() // jichi 8/20/2013: Change return type to boolean
{
  const BYTE bytes[] = {0x66,0x3d,0x1,0x0};
  DWORD start = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  if (!start) {
    ConsoleOutput("vnreng:MalieHook2: pattern not exist");
    return false;
  }
  BYTE *ptr = (BYTE *)start;
  while (true) {
    if (*(WORD *)ptr == 0x3d66) {
      ptr += 4;
      if (ptr[0] == 0x75) {
        ptr += ptr[1]+2;
        continue;
      }
      if (*(WORD *)ptr == 0x850f) {
        ptr += *(DWORD *)(ptr + 2) + 6;
        continue;
      }
    }
    break;
  }
  malie_furi_flag_ = 0; // reset old malie flag
  HookParam hp = {};
  hp.addr = (DWORD)ptr + 4;
  hp.off = -8;
  hp.length_offset = 1;
  hp.text_fun = SpecialHookMalie;
  hp.type = USING_SPLIT|USING_UNICODE|NO_CONTEXT;
  ConsoleOutput("vnreng: INSERT MalieHook2");
  NewHook(hp, L"Malie");
  //RegisterEngineType(ENGINE_MALIE);
  ConsoleOutput("vnreng:Malie2: disable GDI hooks");
  DisableGDIHooks();
  return true;
}

/**
 *  jichi 12/17/2013: Added for Electro Arms
 *  Observations from Electro Arms:
 *  1. split = 0xC can handle most texts and its dwRetn is always zero
 *  2. The text containing furigana needed to split has non-zero dwRetn when split = 0
 *
 *  3/15/2015: logic modified as the plus operation would create so many threads
 */
void SpecialHookMalie2(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  CC_UNUSED(data);
  //*len = GetHookDataLength(*hp, esp_base, (DWORD)data);
  *len = 2;

  DWORD s1 = *(DWORD *)(esp_base + 0xc), // base split, which is stable
        s2 = (*(DWORD *)esp_base); // used to split out furigana, but un stable
  // http://www.binaryhexconverter.com/decimal-to-binary-converter
  //enum : DWORD { mask = 0x14 };
  *split = s1 + (s2 ? 1 : 0);
}

//  static DWORD last_split; // FIXME: This makes the special function stateful
//  DWORD s1 = *(DWORD *)esp_base; // current split at 0x0
//  if (!s1)
//    *split = last_split;
//  else {
//    DWORD s2 = *(DWORD *)(esp_base + 0xc); // second split
//    *split = last_split = s1 + s2; // not sure if plus is a good way
//  }

/**
 *  jichi 8/20/2013: Add hook for sweet light BRAVA!!
 *  See: http://www.hongfire.com/forum/printthread.php?t=36807&pp=10&page=680
 *
 *  BRAVA!! /H code: "/HWN-4:C@1A3DF4:malie.exe"
 *  - addr: 1719796 = 0x1a3df4
 *  - text_fun: 0x0
 *  - function: 0
 *  - hook_len: 0
 *  - ind: 0
 *  - length_offset: 1
 *  - module: 751199171 = 0x2cc663c3
 *  - off: 4294967288 = 0xfffffff8L = -0x8
 *  - recover_len: 0
 *  - split: 12 = 0xc
 *  - split_ind: 0
 *  - type: 1106 = 0x452
 */
bool InsertMalie2Hook()
{
  // 001a3dee    6900 70000000   imul eax,dword ptr ds:[eax],70
  // 001a3df4    0200            add al,byte ptr ds:[eax]   ; this is the place to hook
  // 001a3df6    50              push eax
  // 001a3df7    0069 00         add byte ptr ds:[ecx],ch
  // 001a3dfa    0000            add byte ptr ds:[eax],al
  const BYTE bytes1[] = {
    0x40,            // inc eax
    0x89,0x56, 0x08, // mov dword ptr ds:[esi+0x8],edx
    0x33,0xd2,       // xor edx,edx
    0x89,0x46, 0x04  // mov dword ptr ds:[esi+0x4],eax
  };
  ULONG range1 = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes1, sizeof(bytes1), module_base_, module_base_ + range1);
  //reladdr = 0x1a3df4;
  if (!addr) {
    //ITH_MSG(0, "Wrong1", "t", 0);
    //ConsoleOutput("Not malie2 engine");
    ConsoleOutput("vnreng:Malie2Hook: pattern p not exist");
    return false;
  }

  addr += sizeof(bytes1); // skip bytes1
  //const BYTE bytes2[] = { 0x85, 0xc0 }; // test eax,eax
  const WORD bytes2 = 0xc085; // test eax,eax
  enum { range2 = 0x200 };
  addr = MemDbg::findBytes(&bytes2, sizeof(bytes2), addr, addr + range2);
  if (!addr) {
    //ConsoleOutput("Not malie2 engine");
    ConsoleOutput("vnreng:Malie2Hook: pattern q not exist");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.off = -8; // pusha_eax_off - 4
  hp.length_offset = 1;
  //hp.split = 0xc; // jichi 12/17/2013: Subcontext removed
  //hp.split = -0xc; // jichi 12/17/2013: This could split the furigana, but will mess up the text
  //hp.type = USING_SPLIT|USING_UNICODE|NO_CONTEXT;
  // jichi 12/17/2013: Need extern func for Electro Arms
  // Though the hook parameter is quit similar to Malie, the original extern function does not work
  hp.type = USING_SPLIT|USING_UNICODE|NO_CONTEXT;
  hp.text_fun = SpecialHookMalie2;
  ConsoleOutput("vnreng: INSERT Malie2");
  NewHook(hp, L"Malie2");

  //ITH_GROWL_DWORD2(hp.addr, reladdr);
  //RegisterEngineType(ENGINE_MALIE);
  return true;
}

// jichi 2/8/3014: Return the beginning and the end of the text
// Remove the leading illegal characters
enum { _MALIE3_MAX_LENGTH = VNR_TEXT_CAPACITY };
LPCWSTR _Malie3LTrim(LPCWSTR p)
{
  if (p)
    for (int count = 0; count < _MALIE3_MAX_LENGTH; count++,
        p++)
      if (p[0] == L'v' && p[1] == L'_') { // ex. v_akr0001, v_mzk0001
        p += 9;
        return p; // must return otherwise trimming more will break the ITH repetition elimination
      } else if (p[0] >= 0xa) // ltrim illegal characters less than 0xa
        return p;
  return nullptr;
}
// Remove the trailing illegal characters
LPCWSTR _Malie3RTrim(LPCWSTR p)
{
  if (p)
    for (int count = 0; count < _MALIE3_MAX_LENGTH; count++,
         p--)
      if (p[-1] >= 0xa) { // trim illegal characters less than 0xa
        if (p[-1] >= L'0' && p[-1] <= L'9'&& p[-1-7] == L'_')
          p -= 9;
        else
          return p;
      }
  return nullptr;
}
// Return the end of the line
LPCWSTR _Malie3GetEOL(LPCWSTR p)
{
  if (p)
    for (int count = 0; count < _MALIE3_MAX_LENGTH; count++,
        p++)
      if (p[0] == 0 || p[0] == 0xa) // stop at \0, or \n where the text after 0xa is furigana
        return p;
  return nullptr;
}

/**
 *  jichi 3/8/2014: Add hook for 相州戦神館學園 八命陣
 *  See: http://sakuradite.com/topic/157
 *  check 0x5b51ed for ecx+edx*2
 *  Also need to skip furigana.
 */

void SpecialHookMalie3(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  CC_UNUSED(split);
  DWORD ecx = regof(ecx, esp_base), // *(DWORD *)(esp_base + pusha_ecx_off - 4),
        edx = regof(edx, esp_base); // *(DWORD *)(esp_base + pusha_edx_off - 4);
  //*data = ecx + edx*2; // [ecx+edx*2];
  //*len = wcslen((LPCWSTR)data) << 2;
  // There are garbage characters
  LPCWSTR start = _Malie3LTrim((LPCWSTR)(ecx + edx*2)),
          stop = _Malie3RTrim(_Malie3GetEOL(start));
  *data = (DWORD)start;
  *len = max(0, stop - start) * 2;
  *split = FIXED_SPLIT_VALUE;
  //ITH_GROWL_DWORD5((DWORD)start, (DWORD)stop, *len, (DWORD)*start, (DWORD)_Malie3GetEOL(start));
}

/**
 *  jichi 8/20/2013: Add hook for 相州戦神館學園 八命陣
 *  See: http://sakuradite.com/topic/157
 *  Credits: @ok123
 */
bool InsertMalie3Hook()
{
  const BYTE bytes[] = {
    // 0x90 nop
    0x8b,0x44,0x24, 0x04,   // 5b51e0  mov eax,dword ptr ss:[esp+0x4]
    0x56,                   // 5b51e4  push esi
    0x57,                   // 5b51e5  push edi
    0x8b,0x50, 0x08,        // 5b51e6  mov edx,dword ptr ds:[eax+0x8]
    0x8b,0x08,              // 5b51e9  mov ecx,dword ptr ds:[eax]
    0x33,0xf6,              // 5b51eb  xor esi,esi
    0x66,0x8b,0x34,0x51,    // 5b51ed  mov si,word ptr ds:[ecx+edx*2] // jichi: hook here
    0x42                    // 5b51f1  inc edx
  };
  enum {hook_offset = 0x5b51ed - 0x5b51e0};
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:Malie3: pattern not found");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr + hook_offset;
  //ITH_GROWL(hp.addr);
  //hp.addr = 0x5b51ed;
  //hp.addr = 0x5b51f1;
  //hp.addr = 0x5b51f2;
  // jichi 3/15/2015: Remove 0704 in シルヴァリオ ヴェンデッタ
  hp.filter_fun = IllegalWideCharsFilter;
  hp.text_fun = SpecialHookMalie3;
  hp.type = USING_UNICODE|NO_CONTEXT;
  //hp.filter_fun = Malie3Filter;
  ConsoleOutput("vnreng: INSERT Malie3");
  NewHook(hp, L"Malie3");
  ConsoleOutput("vnreng:Malie3: disable GDI hooks");
  DisableGDIHooks();
  return true;
}

// jichi 3/12/2015: Return guessed Malie engine year
//int GetMalieYear()
//{
//  if (Util::SearchResourceString(L"2013 light"))
//    return 2013;
//  if (Util::SearchResourceString(L"2014 light"))
//    return 2014;
//  return 2015;
//}

} // unnamed Malie

bool InsertMalieHook()
{
  if (IthCheckFile(L"tools.dll"))
    return InsertMalieHook1(); // jichi 3/5/2015: For old light games such as Dies irae.

  else { // For old Malie games before 2015
    // jichi 8/20/2013: Add hook for sweet light engine
    // Insert both malie and malie2 hook.
    bool ok = false;

    // jichi 3/12/2015: Disable MalieHook2 which will crash シルヴァリオ ヴェンデッタ
    //if (!IthCheckFile(L"gdiplus.dll"))
    if (IthFindFile(L"System\\*")) { // Insert old Malie hook. There are usually System/cursor.cur
      ok = InsertMalieHook2() || ok;
      ok = InsertMalie2Hook() || ok; // jichi 8/20/2013
    }

    // The main disadvantage of Malie3 is that it cannot find character name
    ok = InsertMalie3Hook() || ok; // jichi 3/7/2014

    if (ok) {
      ConsoleOutput("vnreng:Malie: disable GDI hooks");
      DisableGDIHooks();
    }
    return ok;
  }
}

/********************************************************************************************
EMEHook hook: (Contributed by Freaka)
  EmonEngine is used by LoveJuice company and TakeOut. Earlier builds were apparently
  called Runrun engine. String parsing varies a lot depending on the font settings and
  speed setting. E.g. without antialiasing (which very early versions did not have)
  uses TextOutA, fast speed triggers different functions then slow/normal. The user can
  set his own name and some odd control characters are used (0x09 for line break, 0x0D
  for paragraph end) which is parsed and put together on-the-fly while playing so script
  can't be read directly.
********************************************************************************************/
bool InsertEMEHook()
{
  ULONG addr = MemDbg::findCallAddress((ULONG)::IsDBCSLeadByte, module_base_, module_limit_);
  // no needed as first call to IsDBCSLeadByte is correct, but sig could be used for further verification
  //WORD sig = 0x51C3;
  //while (c && (*(WORD*)(c-2)!=sig))
  //{
  //  //-0x1000 as FindCallOrJmpAbs always uses an offset of 0x1000
  //  c = Util::FindCallOrJmpAbs((DWORD)IsDBCSLeadByte,module_limit_-c-0x1000+4,c-0x1000+4,false);
  //}
  if (!addr) {
    ConsoleOutput("vnreng:EME: pattern does not exist");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr;
  hp.off = -0x8;
  hp.length_offset = 1;
  hp.type = NO_CONTEXT|DATA_INDIRECT;
  ConsoleOutput("vnreng: INSERT EmonEngine");
  NewHook(hp, L"EmonEngine");
  //ConsoleOutput("EmonEngine, hook will only work with text speed set to slow or normal!");
  //else ConsoleOutput("Unknown EmonEngine engine");
  return true;
}
static void SpecialRunrunEngine(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  CC_UNUSED(split);
  DWORD eax = regof(eax, esp_base), // *(DWORD *)(esp_base - 0x8),
        edx = regof(edx, esp_base); // *(DWORD *)(esp_base - 0x10);
  DWORD addr = eax + edx; // eax + edx
  *data = *(WORD *)(addr);
  *len = 2;
}
bool InsertRREHook()
{
  ULONG addr = MemDbg::findCallAddress((ULONG)::IsDBCSLeadByte, module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:RRE: function call does not exist");
    return false;
  }
  WORD sig = 0x51c3;
  HookParam hp = {};
  hp.addr = addr;
  hp.length_offset = 1;
  hp.type = NO_CONTEXT|DATA_INDIRECT;
  if ((*(WORD *)(addr-2) != sig)) {
    hp.text_fun = SpecialRunrunEngine;
    ConsoleOutput("vnreng: INSERT Runrun#1");
    NewHook(hp, L"RunrunEngine Old");
  } else {
    hp.off = -0x8;
    ConsoleOutput("vnreng: INSERT Runrun#2");
    NewHook(hp, L"RunrunEngine");
  }
  return true;
  //ConsoleOutput("RunrunEngine, hook will only work with text speed set to slow or normal!");
  //else ConsoleOutput("Unknown RunrunEngine engine");
}
bool InsertMEDHook()
{
  for (DWORD i = module_base_; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == 0x8175) //cmp *, 8175
      for (DWORD j = i, k = i + 0x100; j < k; j++)
        if (*(BYTE *)j == 0xe8) {
          DWORD t = j + 5 + *(DWORD*)(j+1);
          if (t > module_base_ && t < module_limit_) {
            HookParam hp = {};
            hp.addr = t;
            hp.off = -0x8;
            hp.length_offset = 1;
            hp.type = BIG_ENDIAN;
            ConsoleOutput("vnreng: INSERT MED");
            NewHook(hp, L"MED");
            //RegisterEngineType(ENGINE_MED);
            return true;
          }
        }

  //ConsoleOutput("Unknown MED engine.");
  ConsoleOutput("vnreng:MED: failed");
  return false;
}
/********************************************************************************************
AbelSoftware hook:
  The game folder usually is made up many no extended name files(file name doesn't have '.').
  And these files have common prefix which is the game name, and 2 digit in order.


********************************************************************************************/
bool InsertAbelHook()
{
  const DWORD character[] = {0xc981d48a, 0xffffff00};
  if (DWORD j = SearchPattern(module_base_, module_limit_ - module_base_, character, sizeof(character))) {
    j += module_base_;
    for (DWORD i = j - 0x100; j > i; j--)
      if (*(WORD *)j == 0xff6a) {
        HookParam hp = {};
        hp.addr = j;
        hp.off = 4;
        hp.type = USING_STRING|NO_CONTEXT;
        ConsoleOutput("vnreng: INSERT AbelSoftware");
        NewHook(hp, L"AbelSoftware");
        //RegisterEngineType(ENGINE_ABEL);
        return true;
      }
  }
  ConsoleOutput("vnreng:Abel: failed");
  return false;
}
bool InsertLiveDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != ::GetGlyphOutlineA || !frame)
    return false;
  DWORD k = *(DWORD *)frame;
  k = *(DWORD *)(k + 4);
  if (*(BYTE *)(k - 5) != 0xe8)
    k = *(DWORD *)(frame + 4);
  DWORD j = k + *(DWORD *)(k - 4);
  if (j > module_base_ && j < module_limit_) {
    HookParam hp = {};
    hp.addr = j;
    hp.off = -0x10;
    hp.length_offset = 1;
    hp.type = BIG_ENDIAN;
    ConsoleOutput("vnreng: INSERT DynamicLive");
    NewHook(hp, L"Live");
    //RegisterEngineType(ENGINE_LIVE);
    return true;
  }
  ConsoleOutput("vnreng:DynamicLive: failed");
  return true; // jichi 12/25/2013: return true
}
//void InsertLiveHook()
//{
//  ConsoleOutput("Probably Live. Wait for text.");
//  trigger_fun_=InsertLiveDynamicHook;
//  SwitchTrigger(true);
//}
bool InsertLiveHook()
{
  const BYTE ins[] = {0x64,0x89,0x20,0x8b,0x45,0x0c,0x50};
  ULONG addr = MemDbg::findBytes(ins, sizeof(ins), module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:Live: pattern not found");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr;
  hp.off = -0x10;
  hp.length_offset = 1;
  hp.type = BIG_ENDIAN;
  ConsoleOutput("vnreng: INSERT Live");
  NewHook(hp, L"Live");
  //RegisterEngineType(ENGINE_LIVE);
  //else ConsoleOutput("Unknown Live engine");
  return true;
}

void InsertBrunsHook()
{
  if (IthCheckFile(L"libscr.dll")) {
    HookParam hp = {};
    hp.off = 4;
    hp.length_offset = 1;
    hp.type = USING_UNICODE|MODULE_OFFSET|FUNCTION_OFFSET;
    // jichi 12/27/2013: This function does not work for the latest bruns games anymore
    hp.function = 0x8b24c7bc;
    //?push_back@?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAEXG@Z
    if (IthCheckFile(L"msvcp90.dll"))
      hp.module = 0xc9c36a5b; // 3385027163
    else if (IthCheckFile(L"msvcp80.dll"))
      hp.module = 0xa9c36a5b; // 2848156251
    else if (IthCheckFile(L"msvcp100.dll")) // jichi 8/17/2013: MSVCRT 10.0 and 11.0
      hp.module = 0xb571d760; // 3044136800;
    else if (IthCheckFile(L"msvcp110.dll"))
      hp.module = 0xd571d760; // 3581007712;
    if (hp.module) {
      ConsoleOutput("vnreng: INSERT Brus#1");
      NewHook(hp, L"Bruns");
    }
  }
  //else
  // jichi 12/21/2013: Keep both bruns hooks
  // The first one does not work for games like 「オーク・キングダム～モン娘繁殖の豚人王～」 anymore.
  {
    union {
      DWORD i;
      DWORD *id;
      WORD *iw;
      BYTE *ib;
    };
    DWORD k = module_limit_ - 4;
    for (i = module_base_ + 0x1000; i < k; i++) {
      if (*id != 0xff) //cmp reg,0xff
        continue;
      i += 4;
      if (*iw != 0x8f0f)
        continue;//jg
      i += 2;
      i += *id + 4;
      for (DWORD j = i + 0x40; i < j; i++) {
        if (*ib != 0xe8)
          continue;
        i++;
        DWORD t = i + 4 + *id;
        if (t > module_base_ && t <module_limit_) {
          i = t;
          for (j = i + 0x80; i < j; i++) {
            if (*ib != 0xe8)
              continue;
            i++;
            t = i + 4 + *id;
            if (t > module_base_ && t <module_limit_) {

              HookParam hp = {};
              hp.addr = t;
              hp.off = 4;
              hp.length_offset = 1;
              hp.type = USING_UNICODE|DATA_INDIRECT;
              ConsoleOutput("vnreng: INSERT Brus#2");
              NewHook(hp, L"Bruns2");
              return;
            }
          }
          k = i; //Terminate outer loop.
          break; //Terminate inner loop.
        }
      }
    }
  }
  //ConsoleOutput("Unknown Bruns engine.");
  ConsoleOutput("vnreng:Brus: failed");
}

/**
 * jichi 8/18/2013:  QLIE identified by GameData/data0.pack
 *
 * The old hook cannot recognize new games.
 */

namespace { // unnamed QLIE
/**
 * jichi 8/18/2013: new QLIE hook
 * See: http://www.hongfire.com/forum/showthread.php/420362-QLIE-engine-Hcode
 *
 * Ins:
 * 55 8B EC 53 8B 5D 1C
 * - 55         push ebp    ; hook here
 * - 8bec       mov ebp, esp
 * - 53         push ebx
 * - 8B5d 1c    mov ebx, dword ptr ss:[ebp+1c]
 *
 * /HBN14*0@4CC2C4
 * - addr: 5030596  (0x4cc2c4)
 * - text_fun: 0x0
 * - function: 0
 * - hook_len: 0
 * - ind: 0
 * - length_offset: 1
 * - module: 0
 * - off: 20    (0x14)
 * - recover_len: 0
 * - split: 0
 * - split_ind: 0
 * - type: 1032 (0x408)
 */
bool InsertQLIE2Hook()
{
  const BYTE bytes[] = { // size = 7
    0x55,           // 55       push ebp    ; hook here
    0x8b,0xec,      // 8bec     mov ebp, esp
    0x53,           // 53       push ebx
    0x8b,0x5d, 0x1c // 8b5d 1c  mov ebx, dword ptr ss:[ebp+1c]
  };
  //enum { hook_offset = 0 }; // current instruction is the first one
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!addr) {
    ConsoleOutput("vnreng:QLIE2: pattern not found");
    //ConsoleOutput("Not QLIE2");
    return false;
  }

  HookParam hp = {};
  hp.type = DATA_INDIRECT|NO_CONTEXT; // 0x408
  hp.length_offset = 1;
  hp.off = 0x14;
  hp.addr = addr;

  ConsoleOutput("vnreng: INSERT QLIE2");
  NewHook(hp, L"QLIE2");
  //ConsoleOutput("QLIE2");
  return true;
}

// jichi: 8/18/2013: Change return type to bool
bool InsertQLIE1Hook()
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == 0x7ffe8347) { //inc edi, cmp esi,7f
      DWORD t = 0;
      for (DWORD j = i; j < i + 0x10; j++) {
        if (*(DWORD *)j == 0xa0) { //cmp esi,a0
          t = 1;
          break;
        }
      }
      if (t)
        for (DWORD j = i; j > i - 0x100; j--)
          if (*(DWORD *)j == 0x83ec8b55) { //push ebp, mov ebp,esp, sub esp,*
            HookParam hp = {};
            hp.addr = j;
            hp.off = 0x18;
            hp.split = -0x18;
            hp.length_offset = 1;
            hp.type = DATA_INDIRECT | USING_SPLIT;
            ConsoleOutput("vnreng: INSERT QLIE1");
            NewHook(hp, L"QLIE");
            //RegisterEngineType(ENGINE_FRONTWING);
            return true;
          }
    }

  ConsoleOutput("vnreng:QLIE1: failed");
  //ConsoleOutput("Unknown QLIE engine");
  return false;
}

} // unnamed QLIE

// jichi 8/18/2013: Add new hook
bool InsertQLIEHook()
{ return InsertQLIE1Hook() || InsertQLIE2Hook(); }

/********************************************************************************************
CandySoft hook:
  Game folder contains many *.fpk. Engine name is SystemC.
  I haven't seen this engine in other company/brand.

  AGTH /X3 will hook lstrlenA. One thread is the exactly result we want.
  But the function call is difficult to located programmatically.
  I find a equivalent points which is more easy to search.
  The script processing function needs to find 0x5B'[',
  so there should a instruction like cmp reg,5B
  Find this position and navigate to function entry.
  The first parameter is the string pointer.
  This approach works fine with game later than つよきす２学期.

  But the original つよきす is quite different. I handle this case separately.

********************************************************************************************/

namespace { // unnamed Candy

// jichi 8/23/2013: split into two different engines
//if (_wcsicmp(process_name_, L"systemc.exe")==0)
// Process name is "SystemC.exe"
bool InsertCandyHook1()
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if ((*(DWORD *)i&0xffffff) == 0x24f980) // cmp cl,24
      for (DWORD j = i, k = i - 0x100; j > k; j--)
        if (*(DWORD *)j == 0xc0330a8a) { // mov cl,[edx]; xor eax,eax
          HookParam hp = {};
          hp.addr = j;
          hp.off = -0x10;
          hp.type = USING_STRING;
          ConsoleOutput("vnreng: INSERT SystemC#1");
          NewHook(hp, L"SystemC");
          //RegisterEngineType(ENGINE_CANDY);
          return true;
        }
  ConsoleOutput("vnreng:CandyHook1: failed");
  return false;
}

// jichi 8/23/2013: Process name is NOT "SystemC.exe"
bool InsertCandyHook2()
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4 ;i++)
    if (*(WORD *)i == 0x5b3c || // cmp al,0x5b
        (*(DWORD *)i & 0xfff8fc) == 0x5bf880) // cmp reg,0x5B
      for (DWORD j = i, k = i - 0x100; j > k; j--)
        if ((*(DWORD *)j & 0xffff) == 0x8b55) { // push ebp, mov ebp,esp, sub esp,*
          HookParam hp = {};
          hp.addr = j;
          hp.off = 4;
          hp.type = USING_STRING;
          ConsoleOutput("vnreng: INSERT SystemC#2");
          NewHook(hp, L"SystemC");
          //RegisterEngineType(ENGINE_CANDY);
          return true;
        }
  ConsoleOutput("vnreng:CandyHook2: failed");
  return false;
}

/** jichi 10/2/2013: CHECKPOINT
 *
 *  [5/31/2013] 恋もHもお勉強も、おまかせ！お姉ちゃん部
 *  base = 0xf20000
 *  + シナリオ: /HSN-4@104A48:ANEBU.EXE
 *    - off: 4294967288 = 0xfffffff8 = -8
 ,    - type: 1025 = 0x401
 *  + 選択肢: /HSN-4@104FDD:ANEBU.EXE
 *    - off: 4294967288 = 0xfffffff8 = -8
 *    - type: 1089 = 0x441
 */
//bool InsertCandyHook3()
//{
//  return false; // CHECKPOINT
//  const BYTE ins[] = {
//    0x83,0xc4, 0x0c, // add esp,0xc ; hook here
//    0x0f,0xb6,0xc0,  // movzx eax,al
//    0x85,0xc0,       // test eax,eax
//    0x75, 0x0e       // jnz XXOO ; it must be 0xe, or there will be duplication
//  };
//  enum { hook_offset = 0 };
//  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
//  ULONG reladdr = SearchPattern(module_base_, range, ins, sizeof(ins));
//  reladdr = 0x104a48;
//  ITH_GROWL_DWORD(module_base_);
//  //ITH_GROWL_DWORD3(reladdr, module_base_, range);
//  if (!reladdr)
//    return false;
//
//  HookParam hp = {};
//  hp.addr = module_base_ + reladdr + hook_offset;
//  hp.off = -8;
//  hp.type = USING_STRING|NO_CONTEXT;
//  NewHook(hp, L"Candy");
//  return true;
//}

} // unnamed Candy

// jichi 10/2/2013: Add new candy hook
bool InsertCandyHook()
{
  if (0 == _wcsicmp(process_name_, L"systemc.exe"))
    return InsertCandyHook1();
  else
    return InsertCandyHook2();
    //bool b2 = InsertCandyHook2(),
    //     b3 = InsertCandyHook3();
    //return b2 || b3;
}

/********************************************************************************************
Apricot hook:
  Game folder contains arc.a*.
  This engine is heavily based on new DirectX interfaces.
  I can't find a good place where text is clean and not repeating.
  The game processes script encoded in UTF32-like format.
  I reversed the parsing algorithm of the game and implemented it partially.
  Only name and text data is needed.

********************************************************************************************/

/** jichi 2/15/2015: ApricoT
 *
 *  Sample game: イセカイ・ラヴァーズ！体験版
 *  Issue of the old game is that it uses esp as split, and hence has relative address
 *
 *  00978100   5b               pop ebx
 *  00978101   83c4 2c          add esp,0x2c
 *  00978104   c2 0400          retn 0x4
 *  00978107   33c0             xor eax,eax ; jichi: hook here
 *  00978109   bb 03000000      mov ebx,0x3
 *  0097810e   895c24 30        mov dword ptr ss:[esp+0x30],ebx
 *  00978112   894424 2c        mov dword ptr ss:[esp+0x2c],eax
 *  00978116   894424 1c        mov dword ptr ss:[esp+0x1c],eax
 *  0097811a   8b4e 34          mov ecx,dword ptr ds:[esi+0x34]
 *  0097811d   3b4e 3c          cmp ecx,dword ptr ds:[esi+0x3c]
 *  00978120   894424 3c        mov dword ptr ss:[esp+0x3c],eax
 *  00978124   7e 3b            jle short .00978161
 *  00978126   8b7e 3c          mov edi,dword ptr ds:[esi+0x3c]
 *  00978129   3b7e 34          cmp edi,dword ptr ds:[esi+0x34]
 *  0097812c   76 05            jbe short .00978133
 *  0097812e   e8 01db1500      call .00ad5c34
 *  00978133   837e 38 04       cmp dword ptr ds:[esi+0x38],0x4
 *  00978137   72 05            jb short .0097813e
 *  00978139   8b46 24          mov eax,dword ptr ds:[esi+0x24]
 *  0097813c   eb 03            jmp short .00978141
 *  0097813e   8d46 24          lea eax,dword ptr ds:[esi+0x24]
 *  00978141   8b3cb8           mov edi,dword ptr ds:[eax+edi*4]
 *  00978144   016e 3c          add dword ptr ds:[esi+0x3c],ebp
 *  00978147   57               push edi
 *  00978148   55               push ebp
 *  00978149   8d4c24 20        lea ecx,dword ptr ss:[esp+0x20]
 *  0097814d   e8 de05feff      call .00958730
 *
 *  Sample stack: baseaddr = 0c90000
 *  001aec2c   ede50fbb
 *  001aec30   0886064c
 *  001aec34   08860bd0
 *  001aec38   08860620
 *  001aec3c   00000000
 *  001aec40   00000000
 *  001aec44   08860bd0
 *  001aec48   001aee18
 *  001aec4c   08860620
 *  001aec50   00000000
 *  001aec54   00cb4408  return to .00cb4408 from .00c973e0
 *  001aec58   08860bd8
 *  001aec5c   00000000
 *  001aec60   001aefd8  pointer to next seh record
 *  001aec64   00e47d88  se handler
 *  001aec68   ffffffff
 *  001aec6c   00cb9f40  return to .00cb9f40 from .00cc8030 ; jichi: split here
 */
static void SpecialHookApricoT(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD reg_esi = *(DWORD *)(esp_base - 0x20);
  DWORD base = *(DWORD *)(reg_esi + 0x24);
  DWORD index = *(DWORD *)(reg_esi + 0x3c);
  DWORD *script = (DWORD *)(base + index * 4);
  // jichi 2/14/2015
  // Change reg_esp to the return address
  //DWORD reg_esp = regof(esp, esp_base);
  //*split = reg_esp;
  //*split = regof(esp, esp_base);
  DWORD arg = argof(16, esp_base); // return address
  *split = arg > module_base_ ? arg - module_base_ : arg; // use relative split value
  //*split = argof(1, esp_base);
  if (script[0] == L'<') {
    DWORD *end;
    for (end = script; *end != L'>'; end++); // jichi 2/14/2015: i.e. = ::wcschr(script) or script
    switch (script[1]) {
    case L'N':
      if (script[2] == L'a' && script[3] == L'm' && script[4] == L'e') {
        buffer_index = 0;
        for (script += 5; script < end; script++)
          if (*script > 0x20)
            wc_buffer[buffer_index++] = *script & 0xFFFF;
        *len = buffer_index<<1;
        *data = (DWORD)wc_buffer;
        // jichi 1/4/2014: The way I save subconext is not able to distinguish the split value
        // Change to shift 16
        //*split |= 1 << 31;
        *split |= 1 << 16; // jichi: differentiate name and text script
      } break;
    case L'T':
      if (script[2] == L'e' && script[3] == L'x' && script[4] == L't') {
        buffer_index = 0;
        for (script += 5; script < end; script++) {
          if (*script > 0x40) {
            while (*script == L'{') {
              script++;
              while (*script!=L'\\') {
                wc_buffer[buffer_index++] = *script & 0xffff;
                script++;
              }
              while (*script++!=L'}');
            }
            wc_buffer[buffer_index++] = *script & 0xffff;
          }
        }
        *len = buffer_index << 1;
        *data = (DWORD)wc_buffer;
      } break;
    }
  }
}

bool InsertApricoTHook()
{
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 4; i++)
    if ((*(DWORD *)i & 0xfff8fc) == 0x3cf880)  // cmp reg,0x3c
      for (DWORD j = i + 3, k = i + 0x100; j < k; j++)
        if ((*(DWORD *)j & 0xffffff) == 0x4c2) { // retn 4
          HookParam hp = {};
          hp.addr = j + 3;
          hp.text_fun = SpecialHookApricoT;
          hp.type = USING_STRING|USING_UNICODE|NO_CONTEXT;
          ConsoleOutput("vnreng: INSERT ApricoT");
          //ITH_GROWL_DWORD3(hp.addr, module_base_, module_limit_);
          NewHook(hp, L"ApRicoT");
          //RegisterEngineType(ENGINE_APRICOT);
          // jichi 2/14/2015: disable cached GDI functions
          ConsoleOutput("vnreng:ApRicoT: disable GDI hooks");
          DisableGDIHooks();
          return true;
        }

  ConsoleOutput("vnreng:ApricoT: failed");
  return false;
}
void InsertStuffScriptHook()
{
  // BOOL GetTextExtentPoint32(
  //   _In_   HDC hdc,
  //   _In_   LPCTSTR lpString,
  //   _In_   int c,
  //   _Out_  LPSIZE lpSize
  // );
  HookParam hp = {};
  hp.addr = (DWORD)::GetTextExtentPoint32A;
  hp.off = 0x8; // arg2 lpString
  hp.split = -0x18; // jichi 8/12/2014: = -4 - pusha_esp_off
  hp.type = USING_STRING | USING_SPLIT;
  ConsoleOutput("vnreng: INSERT StuffScriptEngine");
  NewHook(hp, L"StuffScriptEngine");
  //RegisterEngine(ENGINE_STUFFSCRIPT);
}
bool InsertTriangleHook()
{
  for (DWORD i = module_base_; i < module_limit_ - 4; i++)
    if ((*(DWORD *)i & 0xffffff) == 0x75403c) // cmp al,0x40; jne
      for (DWORD j = i + 4 + *(BYTE*)(i+3), k = j + 0x20; j < k; j++)
        if (*(BYTE*)j == 0xe8) {
          DWORD t = j + 5 + *(DWORD *)(j + 1);
          if (t > module_base_ && t < module_limit_) {
            HookParam hp = {};
            hp.addr = t;
            hp.off = 4;
            hp.type = USING_STRING;
            ConsoleOutput("vnreng: INSERT Triangle");
            NewHook(hp, L"Triangle");
            //RegisterEngineType(ENGINE_TRIANGLE);
            return true;
          }
        }
  //ConsoleOutput("Old/Unknown Triangle engine.");
  ConsoleOutput("vnreng:Triangle: failed");
  return false;
}
bool InsertPensilHook()
{
  for (DWORD i = module_base_; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == 0x6381) // cmp *,8163
      if (DWORD j = SafeFindEntryAligned(i, 0x100)) {
        HookParam hp = {};
        hp.addr = j;
        hp.off = 8;
        hp.length_offset = 1;
        ConsoleOutput("vnreng: INSERT Pensil");
        NewHook(hp, L"Pensil");
        return true;
        //RegisterEngineType(ENGINE_PENSIL);
      }
  //ConsoleOutput("Unknown Pensil engine.");
  ConsoleOutput("vnreng:Pensil: failed");
  return false;
}
#if 0 // jich 3/8/2015: disabled
bool IsPensilSetup()
{
  HANDLE hFile = IthCreateFile(L"PSetup.exe", FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
  FILE_STANDARD_INFORMATION info;
  IO_STATUS_BLOCK ios;
  LPVOID buffer = nullptr;
  NtQueryInformationFile(hFile, &ios, &info, sizeof(info), FileStandardInformation);
  NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0,
      &info.AllocationSize.LowPart, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  NtReadFile(hFile, 0,0,0, &ios, buffer, info.EndOfFile.LowPart, 0, 0);
  NtClose(hFile);
  BYTE *b = (BYTE *)buffer;
  DWORD len = info.EndOfFile.LowPart & ~1;
  if (len == info.AllocationSize.LowPart)
    len -= 2;
  b[len] = 0;
  b[len + 1] = 0;
  bool ret = wcsstr((LPWSTR)buffer, L"PENSIL") || wcsstr((LPWSTR)buffer, L"Pensil");
  NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &info.AllocationSize.LowPart, MEM_RELEASE);
  return ret;
}
#endif // if 0
static void SpecialHookDebonosu(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD retn = *(DWORD*)esp_base;
  if (*(WORD*)retn == 0xc483) // add esp, *
    hp->off = 4;
  else
    hp->off = -0x8;
  //hp->type ^= EXTERN_HOOK;
  hp->text_fun = nullptr;
  *data = *(DWORD*)(esp_base + hp->off);
  *len = ::strlen((char*)*data);
}
bool InsertDebonosuHook()
{
  DWORD fun;
  if (CC_UNLIKELY(!GetFunctionAddr("lstrcatA", &fun, 0, 0, 0))) {
    ConsoleOutput("vnreng:Debonosu: failed to find lstrcatA");
    return false;
  }
  DWORD addr = Util::FindImportEntry(module_base_, fun);
  if (!addr) {
    ConsoleOutput("vnreng:Debonosu: lstrcatA is not called");
    return false;
  }
  DWORD search = 0x15ff | (addr << 16); // jichi 10/20/2014: call dword ptr ds
  addr >>= 16;
  for (DWORD i = module_base_; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == search &&
        *(WORD *)(i + 4) == addr && // call dword ptr lstrcatA
        *(BYTE *)(i - 5) == 0x68) { // push $
      DWORD push = *(DWORD *)(i - 4);
      for (DWORD j = i + 6, k = j + 0x10; j < k; j++)
        if (*(BYTE *)j == 0xb8 &&
            *(DWORD *)(j + 1) == push)
          if (DWORD hook_addr = SafeFindEntryAligned(i, 0x200)) {
            HookParam hp = {};
            hp.addr = hook_addr;
            hp.text_fun = SpecialHookDebonosu;
            hp.type = USING_STRING;
            ConsoleOutput("vnreng: INSERT Debonosu");
            NewHook(hp, L"Debonosu");
            //RegisterEngineType(ENGINE_DEBONOSU);
            return true;
          }
      }

  ConsoleOutput("vnreng:Debonosu: failed");
  //ConsoleOutput("Unknown Debonosu engine.");
  return false;
}

/* 7/8/2014: The engine name is supposed to be: AoiGameSystem Engine
 * See: http://capita.tistory.com/m/post/205
 *
 *  BUNNYBLACK Trial2 (SystemAoi4)
 *  baseaddr: 0x01d0000
 *
 *  1002472e   cc               int3
 *  1002472f   cc               int3
 *  10024730   55               push ebp    ; jichi: hook here
 *  10024731   8bec             mov ebp,esp
 *  10024733   51               push ecx
 *  10024734   c745 fc 00000000 mov dword ptr ss:[ebp-0x4],0x0
 *  1002473b   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  1002473e   0fb708           movzx ecx,word ptr ds:[eax]
 *  10024741   85c9             test ecx,ecx
 *  10024743   74 34            je short _8.10024779
 *  10024745   6a 00            push 0x0
 *  10024747   6a 00            push 0x0
 *  10024749   6a 01            push 0x1
 *  1002474b   8b55 14          mov edx,dword ptr ss:[ebp+0x14]
 *  1002474e   52               push edx
 *  1002474f   0fb645 10        movzx eax,byte ptr ss:[ebp+0x10]
 *  10024753   50               push eax
 *  10024754   0fb74d 0c        movzx ecx,word ptr ss:[ebp+0xc]
 *  10024758   51               push ecx
 *  10024759   8b55 08          mov edx,dword ptr ss:[ebp+0x8]
 *  1002475c   52               push edx
 *  1002475d   e8 8eddffff      call _8.100224f0
 *  10024762   83c4 1c          add esp,0x1c
 *  10024765   8945 fc          mov dword ptr ss:[ebp-0x4],eax
 *  10024768   8b45 1c          mov eax,dword ptr ss:[ebp+0x1c]
 *  1002476b   50               push eax
 *  1002476c   8b4d 18          mov ecx,dword ptr ss:[ebp+0x18]
 *  1002476f   51               push ecx
 *  10024770   8b55 fc          mov edx,dword ptr ss:[ebp-0x4]
 *  10024773   52               push edx
 *  10024774   e8 77c6ffff      call _8.10020df0
 *  10024779   8b45 fc          mov eax,dword ptr ss:[ebp-0x4]
 *  1002477c   8be5             mov esp,ebp
 *  1002477e   5d               pop ebp
 *  1002477f   c2 1800          retn 0x18
 *  10024782   cc               int3
 *  10024783   cc               int3
 *  10024784   cc               int3
 *
 *  2/12/2015 jichi: SystemAoi5
 *
 *  Note that BUNNYBLACK 3 also has SystemAoi5 version 4.1
 *
 *  Hooked to PgsvTd.dll for all SystemAoi engine, which contains GDI functions.
 *  - Old: AoiLib.dll from DrawTextExA
 *  - SystemAoi4: Aoi4.dll from DrawTextExW
 *  - SystemAoi5: Aoi5.dll from GetGlyphOutlineW
 *
 *  Logic:
 *  - Find GDI function (DrawTextExW, etc.) used to paint text in PgsvTd.dll
 *  - Then search the function call stack, to find where the exe module invoke PgsvTd
 *  - Finally insert to the call address, and text is on the top of the stack.
 *
 *  Sample hooked call in 悪魔娘の看板料理 Aoi5
 *
 *  00B6D085   56               PUSH ESI
 *  00B6D086   52               PUSH EDX
 *  00B6D087   51               PUSH ECX
 *  00B6D088   68 9E630000      PUSH 0x639E
 *  00B6D08D   50               PUSH EAX
 *  00B6D08E   FF15 54D0BC00    CALL DWORD PTR DS:[0xBCD054]             ; _12.0039E890, jichi: hook here
 *  00B6D094   8B57 20          MOV EDX,DWORD PTR DS:[EDI+0x20]
 *  00B6D097   89049A           MOV DWORD PTR DS:[EDX+EBX*4],EAX
 *  00B6D09A   8B4F 20          MOV ECX,DWORD PTR DS:[EDI+0x20]
 *  00B6D09D   8B1499           MOV EDX,DWORD PTR DS:[ECX+EBX*4]
 *  00B6D0A0   8D85 50FDFFFF    LEA EAX,DWORD PTR SS:[EBP-0x2B0]
 *  00B6D0A6   50               PUSH EAX
 *  00B6D0A7   52               PUSH EDX
 *  00B6D0A8   FF15 18D0BC00    CALL DWORD PTR DS:[0xBCD018]             ; _12.003A14A0
 *
 *  Special hook is needed, since the utf16 text is like this:
 *  [f9S30e0u]　が、それは人間相手の話だ。
 */
namespace { // unnamed
void SpecialSystemAoiHook(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  *split = 0; // 8/3/2014 jichi: split is zero, so return address is used as split
  if (hp->type & USING_UNICODE) {
    LPCWSTR wcs = (LPWSTR)argof(1, esp_base); // jichi: text on the top of the stack
    size_t size = ::wcslen(wcs);
    for (DWORD i = 0; i < size; i++)
      if (wcs[i] == L'>' || wcs[i] == L']') { // skip leading ] for scenario and > for name threads
        *data = (DWORD)(wcs + i + 1);
        size -= i + 1;
        *len = size * 2; // * 2 for wstring
        return;
      }
  } else {
    LPCSTR cs = (LPCSTR)argof(1, esp_base); // jichi: text on the top of the stack
    size_t size = ::strlen(cs);
    for (DWORD i = 0; i < size; i++)
      if (cs[i] == '>' || cs[i] == ']') {
        *data = (DWORD)(cs + i + 1);
        size -= i + 1;
        *len = size;
        return;
      }
  }
}

int GetSystemAoiVersion() // return result is cached
{
  static int ret = 0;
  if (!ret) {
    if (IthCheckFile(L"Aoi4.dll"))
      ret = 4;
    else if (IthCheckFile(L"Aoi5.dll"))
      ret = 5;
    else if (IthCheckFile(L"Aoi6.dll")) // not exist yet, for future version
      ret = 6;
    else if (IthCheckFile(L"Aoi7.dll")) // not exist yet, for future version
      ret = 7;
    else // AoiLib.dll, etc
      ret = 3;
  }
  return ret;
}

bool InsertSystemAoiDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  int version = GetSystemAoiVersion();
  bool utf16 = true;
  if (addr == ::DrawTextExA) // < 4
    utf16 = false;
  if (addr == ::DrawTextExW) // 4~5
    ; // pass
  else if (addr == ::GetGlyphOutlineW && version >= 5)
    ; // pass
  else
    return false;

  DWORD high, low;
  Util::GetCodeRange(module_base_, &low, &high);

  // jichi 2/15/2015: Traverse the stack to dynamically find the ancestor call from the main module
  const DWORD stop = (stack & 0xffff0000) + 0x10000; // range to traverse the stack
  for (DWORD i = stack; i < stop; i += 4) {
    DWORD k = *(DWORD *)i;
    if (k > low && k < high && // jichi: if the stack address falls into the code region of the main exe module
        ((*(WORD *)(k - 6) == 0x15ff) || *(BYTE *)(k - 5) == 0xe8)) { // jichi 10/20/2014: call dword ptr ds

      HookParam hp = {};
      hp.off = 0x4; // target text is on the top of the stack
      hp.text_fun = SpecialSystemAoiHook; // need to remove garbage
      hp.type = utf16 ? USING_UNICODE : USING_STRING;

      i = *(DWORD *)(k - 4); // get function call address
      if (*(DWORD *)(k - 5) == 0xe8) // short jump
        hp.addr = i + k;
      else
        hp.addr = *(DWORD *)i; // jichi: long jump, this is what is happening in Aoi5
      //NewHook(hp, L"SofthouseChara");
      //ITH_GROWL_DWORD(hp.addr); // BUNNYBLACK: 0x10024730, base 0x01d0000
      if (hp.addr) {
        ConsoleOutput("vnreng: INSERT SystemAoi");
        if (addr == ::GetGlyphOutlineW)
          NewHook(hp, L"SystemAoi2"); // jichi 2/12/2015
        else
          NewHook(hp, L"SystemAoi"); // jichi 7/8/2014: renamed, see: ja.wikipedia.org/wiki/ソフトハウスキャラ
        ConsoleOutput("vnreng:SystemAoi: disable GDI hooks");
        DisableGDIHooks();
      } else
        ConsoleOutput("vnreng: failed to detect SystemAoi");
      //RegisterEngineType(ENGINE_SOFTHOUSE);
      return true;
    }
  }
  ConsoleOutput("vnreng:SystemAoi: failed");
  return true; // jichi 12/25/2013: return true
}

} // unnamed namespace

bool InsertSystemAoiHook()
{
  ConsoleOutput("vnreng: DYNAMIC SystemAoi");
  //ConsoleOutput("Probably SoftHouseChara. Wait for text.");
  trigger_fun_ = InsertSystemAoiDynamicHook;
  SwitchTrigger(true);
  return true;
}

static void SpecialHookCaramelBox(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD reg_ecx = *(DWORD*)(esp_base + hp->off);
  BYTE *ptr = (BYTE *)reg_ecx;
  buffer_index = 0;
  while (ptr[0])
    if (ptr[0] == 0x28) { // Furigana format: (Kanji,Furi)
      ptr++;
      while (ptr[0]!=0x2c) //Copy Kanji
        text_buffer[buffer_index++] = *ptr++;
      while (ptr[0]!=0x29) // Skip Furi
        ptr++;
      ptr++;
    } else if (ptr[0] == 0x5c)
      ptr +=2;
    else {
      text_buffer[buffer_index++] = ptr[0];
      if (LeadByteTable[ptr[0]] == 2) {
        ptr++;
        text_buffer[buffer_index++] = ptr[0];
      }
      ptr++;
    }

  *len = buffer_index;
  *data = (DWORD)text_buffer;
  *split = 0; // 8/3/2014 jichi: use return address as split
}
// jichi 10/1/2013: Change return type to bool
bool InsertCaramelBoxHook()
{
  union { DWORD i; BYTE* pb; WORD* pw; DWORD *pd; };
  DWORD reg = -1;
  for (i = module_base_ + 0x1000; i < module_limit_ - 4; i++) {
    if (*pd == 0x7ff3d) // cmp eax, 7ff
      reg = 0;
    else if ((*pd & 0xfffff8fc) == 0x07fff880) // cmp reg, 7ff
      reg = pb[1] & 0x7;

    if (reg == -1)
      continue;

    DWORD flag = 0;
    if (*(pb - 6) == 3) { //add reg, [ebp+$disp_32]
      if (*(pb - 5) == (0x85 | (reg << 3)))
        flag = 1;
    } else if (*(pb - 3) == 3) { // add reg, [ebp+$disp_8]
      if (*(pb - 2) == (0x45 | (reg << 3)))
        flag = 1;
    } else if (*(pb - 2) == 3) { // add reg, reg
      if (((*(pb - 1) >> 3) & 7)== reg)
        flag = 1;
    }
    reg = -1;
    if (flag) {
      for (DWORD j = i, k = i - 0x100; j > k; j--) {
        if ((*(DWORD *)j & 0xffff00ff) == 0x1000b8) { // mov eax,10??
          HookParam hp = {};
          hp.addr = j & ~0xf;
          hp.text_fun = SpecialHookCaramelBox;
          hp.type = USING_STRING ;
          for (i &= ~0xffff; i < module_limit_ - 4; i++)
            if (pb[0] == 0xe8) {
              pb++;
              if (pd[0] + i + 4 == hp.addr) {
                pb += 4;
                if ((pd[0] & 0xffffff) == 0x04c483)
                  hp.off = 4;
                else hp.off = -0xc;
                break;
              }
            }

          if (hp.off == 0) {
            ConsoleOutput("vnreng:CaramelBox: failed, zero off");
            return false;
          }
          ConsoleOutput("vnreng: INSERT CaramelBox");
          NewHook(hp, L"CaramelBox");
          //RegisterEngineType(ENGINE_CARAMEL);
          return true;
        }
      }
    }
  }
  ConsoleOutput("vnreng:CaramelBox: failed");
  return false;
//_unknown_engine:
  //ConsoleOutput("Unknown CarmelBox engine.");
}

/**
 *  jichi 10/12/2014
 *  P.S.: Another approach
 *  See: http://tieba.baidu.com/p/2425786155
 *  Quote:
 *  I guess this post should go in here. I got sick of AGTH throwing a fit when entering the menus in Wolf RPG games, so I did some debugging. This is tested and working properly with lots of games. If you find one that isn't covered then please PM me and I'll look into it.
 *
 *  Wolf RPG H-code - Use whichever closest matches your Game.exe
 *  /HBN*0@454C6C (2010/10/09 : 2,344KB : v1.31)
 *  /HBN*0@46BA03 (2011/11/22 : 2,700KB : v2.01)
 *  /HBN*0@470CEA (2012/05/07 : 3,020KB : v2.02)
 *  /HBN*0@470D5A (2012/06/10 : 3,020KB : v2.02a)
 *
 *  ith_p.cc:Ith::parseHookCode: enter: code = "/HBN*0@470CEA"
 *  - addr: 4656362 ,
 *  - length_offset: 1
 *  - type: 1032 = 0x408
 *
 *  Use /HB instead of /HBN if you want to split dialogue text and menu text into separate threads.
 *  Also set the repetition trace parameters in AGTH higher or it won't work properly with text-heavy menus. 64 x 16 seems to work fine.
 *
 *  Issues:
 *  AGTH still causes a bit of lag when translating menus if you have a lot of skills or items.
 *  Using ITH avoids this problem, but it sometimes has issues with repetition detection which can be fixed by quickly deselecting and reselecting the game window; Personally I find this preferable to menu and battle slowdown that AGTH sometimes causes, but then my PC is pretty slow so you might not have that problem.
 *
 *  Minimising the AGTH/ITH window generally makes the game run a bit smoother as windows doesn't need to keep scrolling the text box as new text is added.
 *
 *  RPG Maker VX H-code:
 *  Most games are detected automatically and if not then by using the AGTH /X or /X2 or /X3 parameters.
 *
 *  Games that use TRGSSX.dll may have issues with detection (especially with ITH).
 *  If TRGSSX.dll is included with the game then this code should work:
 *  /HQN@D3CF:TRGSSX.dll
 *
 *  With this code, using AGTH to start the process will not work. You must start the game normally and then hook the process afterwards.
 *  ITH has this functionality built into the interface. AGTH requires the /PN command line argument, for example:
 *  agth /PNGame.exe /HQN@D3CF:TRGSSX.dll /C
 *
 *  Again, drop the N to split dialogue and menu text into separate threads.
 */
// jichi 10/13/2013: restored
bool InsertWolfHook()
{
  //__asm int 3   // debug
  // jichi 10/12/2013:
  // Step 1: find the address of GetTextMetricsA
  // Step 2: find where this function is called
  // Step 3: search "sub esp, XX" after where it is called
  enum { sub_esp = 0xec81 }; // jichi: caller pattern: sub esp = 0x81,0xec
  if (DWORD c1 = Util::FindCallAndEntryAbs((DWORD)GetTextMetricsA, module_limit_ - module_base_, module_base_, sub_esp))
    if (DWORD c2 = Util::FindCallOrJmpRel(c1, module_limit_ - module_base_, module_base_, 0)) {
      union {
        DWORD i;
        WORD *k;
      };
      DWORD j;
      for (i = c2 - 0x100, j = c2 - 0x400; i > j; i--)
        if (*k == 0xec83) { // jichi 10/12/2013: 83 EC XX   sub esp, XX  See: http://lists.cs.uiuc.edu/pipermail/llvm-commits/Week-of-Mon-20120312.txt
          HookParam hp = {};
          hp.addr = i;
          hp.off = -0xc;
          hp.split = -0x18;
          hp.type = DATA_INDIRECT|USING_SPLIT;
          hp.length_offset = 1;
          //ITH_GROWL_DWORD(hp.addr); // jichi 6/5/2014: 淫乱勇者セフィのRPG = 0x50a400
          ConsoleOutput("vnreng: INSERT WolfRPG");
          NewHook(hp, L"WolfRPG");
          return true;
        }
    }

  //ConsoleOutput("Unknown WolfRPG engine.");
  ConsoleOutput("vnreng:WolfRPG: failed");
  return false;
}

bool InsertIGSDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != GetGlyphOutlineW)
    return false;
  DWORD i;
  i = *(DWORD *)frame;
  i = *(DWORD *)(i+4);
  DWORD j, k;
  if (SafeFillRange(L"mscorlib.ni.dll", &j, &k)) {
    while (*(BYTE *)i != 0xe8)
      i++;
    DWORD t = *(DWORD *)(i + 1) + i + 5;
    if (t>j && t<k) {
      HookParam hp = {};
      hp.addr = t;
      hp.off = -0x10;
      hp.split = -0x18;
      hp.length_offset = 1;
      hp.type = USING_UNICODE|USING_SPLIT;
      ConsoleOutput("vnreng: INSERT IronGameSystem");
      NewHook(hp, L"IronGameSystem");
      //ConsoleOutput("IGS - Please set text(テキスト) display speed(表示速度) to fastest(瞬間)");
      //RegisterEngineType(ENGINE_IGS);
      return true;
    }
  }
  ConsoleOutput("vnreng:IGS: failed");
  return true; // jichi 12/25/2013: return true
}
void InsertIronGameSystemHook()
{
  //ConsoleOutput("Probably IronGameSystem. Wait for text.");
  trigger_fun_ = InsertIGSDynamicHook;
  SwitchTrigger(true);
  ConsoleOutput("vnreng: TRIGGER IronGameSystem");
}

/********************************************************************************************
AkabeiSoft2Try hook:
  Game folder contains YaneSDK.dll. Maybe we should call the engine Yane(屋根 = roof)?
  This engine is based on .NET framework. This really makes it troublesome to locate a
  valid hook address. The problem is that the engine file merely contains bytecode for
  the CLR. Real meaningful object code is generated dynamically and the address is randomized.
  Therefore the easiest method is to brute force search whole address space. While it's not necessary
  to completely search the whole address space, since non-executable pages can be excluded first.
  The generated code sections do not belong to any module(exe/dll), hence they do not have
  a section name. So we can also exclude executable pages from all modules. At last, the code
  section should be long(>0x2000). The remain address space should be several MBs in size and
  can be examined in reasonable time(less than 0.1s for P8400 Win7x64).
  Characteristic sequence is 0F B7 44 50 0C, stands for movzx eax, word ptr [edx*2 + eax + C].
  Obviously this instruction extracts one unicode character from a string.
  A main shortcoming is that the code is not generated if it hasn't been used yet.
  So if you are in title screen this approach will fail.

********************************************************************************************/
namespace { // unnamed
MEMORY_WORKING_SET_LIST *GetWorkingSet()
{
  DWORD len,retl;
  NTSTATUS status;
  LPVOID buffer = 0;
  len = 0x4000;
  status = NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &len, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
  if (!NT_SUCCESS(status)) return 0;
  status = NtQueryVirtualMemory(NtCurrentProcess(), 0, MemoryWorkingSetList, buffer, len, &retl);
  if (status == STATUS_INFO_LENGTH_MISMATCH) {
    len = *(DWORD*)buffer;
    len = ((len << 2) & 0xfffff000) + 0x4000;
    retl = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &retl, MEM_RELEASE);
    buffer = 0;
    status = NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &len, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) return 0;
    status = NtQueryVirtualMemory(NtCurrentProcess(), 0, MemoryWorkingSetList, buffer, len, &retl);
    if (!NT_SUCCESS(status)) return 0;
    return (MEMORY_WORKING_SET_LIST*)buffer;
  } else {
    retl = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &retl, MEM_RELEASE);
    return 0;
  }

}
typedef struct _NSTRING
{
  PVOID vfTable;
  DWORD lenWithNull;
  DWORD lenWithoutNull;
  WCHAR str[1];
} NSTRING;

// qsort correctly identifies overflow.
int cmp(const void * a, const void * b)
{ return *(int*)a - *(int*)b; }

void SpecialHookAB2Try(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  //DWORD test = *(DWORD*)(esp_base - 0x10);
  DWORD edx = regof(edx, esp_base);
  if (edx != 0)
    return;

  //NSTRING *s = *(NSTRING **)(esp_base - 8);
  if (const NSTRING *s = (NSTRING *)regof(eax, esp_base)) {
    *len = s->lenWithoutNull << 1;
    *data = (DWORD)s->str;
    //*split = 0;
    *split = FIXED_SPLIT_VALUE; // 8/3/2014 jichi: change to single threads
  }
}

BOOL FindCharacteristInstruction(MEMORY_WORKING_SET_LIST *list)
{
  DWORD base, size;
  DWORD i, j, k, addr, retl;
  NTSTATUS status;
  ::qsort(&list->WorkingSetList, list->NumberOfPages, 4, cmp);
  base = list->WorkingSetList[0];
  size = 0x1000;
  for (i = 1; i < list->NumberOfPages; i++) {
    if ((list->WorkingSetList[i] & 2) == 0)
      continue;
    if (list->WorkingSetList[i] >> 31)
      break;
    if (base + size == list->WorkingSetList[i])
      size += 0x1000;
    else {
      if (size > 0x2000) {
        addr = base & ~0xfff;
        status = NtQueryVirtualMemory(NtCurrentProcess(),(PVOID)addr,
          MemorySectionName,text_buffer_prev,0x1000,&retl);
        if (!NT_SUCCESS(status)) {
          k = addr + size - 4;
          for (j = addr; j < k; j++) {
            if (*(DWORD*)j == 0x5044b70f) {
              if (*(WORD*)(j + 4) == 0x890c) { // movzx eax, word ptr [edx*2 + eax + 0xC]; wchar = string[i];
                HookParam hp = {};
                hp.addr = j;
                hp.text_fun = SpecialHookAB2Try;
                hp.type = USING_STRING|USING_UNICODE|NO_CONTEXT;
                ConsoleOutput("vnreng: INSERT AB2Try");
                NewHook(hp, L"AB2Try");
                //ConsoleOutput("Please adjust text speed to fastest/immediate.");
                //RegisterEngineType(ENGINE_AB2T);
                return TRUE;
              }
            }
          }
        }
      }
      size = 0x1000;
      base = list->WorkingSetList[i];
    }
  }
  return FALSE;
}
} // unnamed namespace
bool InsertAB2TryHook()
{
  MEMORY_WORKING_SET_LIST *list = GetWorkingSet();
  if (!list) {
    ConsoleOutput("vnreng:AB2Try: cannot find working list");
    return false;
  }
  bool ret = FindCharacteristInstruction(list);
  if (ret)
    ConsoleOutput("vnreng:AB2Try: found characteristic sequence");
  else
    ConsoleOutput("vnreng:AB2Try: cannot find characteristic sequence");
  //L"Make sure you have start the game and have seen some text on the screen.");
  DWORD size = 0;
  NtFreeVirtualMemory(NtCurrentProcess(), (PVOID *)&list, &size, MEM_RELEASE);
  return ret;
}

/********************************************************************************************
C4 hook: (Contributed by Stomp)
  Game folder contains C4.EXE or XEX.EXE.
********************************************************************************************/
bool InsertC4Hook()
{
  const BYTE bytes[] = { 0x8a, 0x10, 0x40, 0x80, 0xfa, 0x5f, 0x88, 0x15 };
  //enum { hook_offset = 0 };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:C4: pattern not found");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr;
  hp.off = -0x8;
  hp.type = DATA_INDIRECT|NO_CONTEXT;
  hp.length_offset = 1;
  ConsoleOutput("vnreng: INSERT C4");
  NewHook(hp, L"C4");
  //RegisterEngineType(ENGINE_C4);
  return true;
}

/** 1/18/2015 jichi Add new WillPlus
 *  The old hook no longer works for new game.
 *  Sample game: [150129] [honeybee] RE:BIRTHDAY SONG
 *
 *  Note, WillPlus engine is migrating to UTF16 using GetGlyphOutlineW such as:
 *      [141218] [Guily] 手籠めにされる九人の堕女
 *  This engine does not work for GetGlyphOutlineW, which, however, does not need a H-code.
 *
 *  See: http://sakuradite.com/topic/615
 *
 *  There WillPlus games have many hookable threads.
 *  But it is kind of important to find the best one.
 *
 *  By inserting hw point:
 *  - There is a clean text thread with fixed memory address.
 *    However, it cannot extract character name like GetGlyphOutlineA.
 *  - This is a non-clean text thread, but it contains garbage such as %LC.
 *
 *  By backtracking from GetGlyphOutlineA:
 *  - GetGlyphOutlineA sometimes can extract all text, sometimes not.
 *  - There are two GetGlyphOutlineA functions.
 *    Both of them are called statically in the same function.
 *    That function is hooked.
 *
 *  Hooked function:
 *  0041820c   cc               int3
 *  0041820d   cc               int3
 *  0041820e   cc               int3
 *  0041820f   cc               int3
 *  00418210   81ec b4000000    sub esp,0xb4
 *  00418216   8b8424 c4000000  mov eax,dword ptr ss:[esp+0xc4]
 *  0041821d   53               push ebx
 *  0041821e   8b9c24 d0000000  mov ebx,dword ptr ss:[esp+0xd0]
 *  00418225   55               push ebp
 *  00418226   33ed             xor ebp,ebp
 *  00418228   56               push esi
 *  00418229   8bb424 dc000000  mov esi,dword ptr ss:[esp+0xdc]
 *  00418230   03c3             add eax,ebx
 *  00418232   57               push edi
 *  00418233   8bbc24 d8000000  mov edi,dword ptr ss:[esp+0xd8]
 *  0041823a   896c24 14        mov dword ptr ss:[esp+0x14],ebp
 *  0041823e   894424 4c        mov dword ptr ss:[esp+0x4c],eax
 *  00418242   896c24 24        mov dword ptr ss:[esp+0x24],ebp
 *  00418246   39ac24 e8000000  cmp dword ptr ss:[esp+0xe8],ebp
 *  0041824d   75 29            jnz short .00418278
 *  0041824f   c74424 24 010000>mov dword ptr ss:[esp+0x24],0x1
 *
 *  ...
 *
 *  00418400   56               push esi
 *  00418401   52               push edx
 *  00418402   ff15 64c04b00    call dword ptr ds:[0x4bc064]             ; gdi32.getglyphoutlinea
 *  00418408   8bf8             mov edi,eax
 *
 *  The old WillPlus engine can also be inserted to the new games.
 *  But it has no effects.
 *
 *  A split value is used to get saving message out.
 *
 *  Runtime stack for the scenario thread:
 *  0012d9ec   00417371  return to .00417371 from .00418210
 *  0012d9f0   00000003  1
 *  0012d9f4   00000000  2
 *  0012d9f8   00000130  3
 *  0012d9fc   0000001a  4
 *  0012da00   0000000b  5
 *  0012da04   00000016  6
 *  0012da08   0092fc00  .0092fc00 ms gothic ; jichi: here's font
 *  0012da0c   00500aa0  .00500aa0 shun ; jichi: text is here in arg8
 *  0012da10   0217dcc0
 *
 *  Runtime stack for name:
 *  0012d9ec   00417371  return to .00417371 from .00418210
 *  0012d9f0   00000003
 *  0012d9f4   00000000
 *  0012d9f8   00000130
 *  0012d9fc   0000001a
 *  0012da00   0000000b
 *  0012da04   00000016
 *  0012da08   0092fc00  .0092fc00
 *  0012da0c   00500aa0  .00500aa0
 *  0012da10   0217dcc0
 *  0012da14   00000000
 *  0012da18   00000000
 *
 *  Runtime stack for non-dialog scenario text.
 *  0012e5bc   00438c1b  return to .00438c1b from .00418210
 *  0012e5c0   00000006
 *  0012e5c4   00000000
 *  0012e5c8   000001ae
 *  0012e5cc   000000c8
 *  0012e5d0   0000000c
 *  0012e5d4   00000018
 *  0012e5d8   0092fc00  .0092fc00
 *  0012e5dc   0012e628
 *  0012e5e0   0b0d0020
 *  0012e5e4   004fda98  .004fda98
 *
 *  Runtime stack for saving message
 *  0012ed44   00426003  return to .00426003 from .00418210
 *  0012ed48   000003c7
 *  0012ed4c   00000000
 *  0012ed50   000000d8
 *  0012ed54   0000012f
 *  0012ed58   00000008
 *  0012ed5c   00000010
 *  0012ed60   0092fc00  .0092fc00
 *  0012ed64   00951d88  ascii "2015/01/18"
 */

#if 0
static bool InsertWillPlusHook2() // jichi 1/18/2015: Add new hook
{
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:WillPlus2: failed to get memory range");
    return false;
  }

  // The following won't work after inserting WillPlus1, which also produces int3
  //ULONG addr = MemDbg::findCallerAddressAfterInt3((DWORD)::GetGlyphOutlineA, startAddress, stopAddress);

  // 00418210   81ec b4000000    sub esp,0xb4
  enum { sub_esp = 0xec81 }; // jichi: caller pattern: sub esp = 0x81,0xec
  ULONG addr = MemDbg::findCallerAddress((ULONG)::GetGlyphOutlineA, sub_esp, startAddress, stopAddress);
  if (!addr) {
    ConsoleOutput("vnreng:WillPlus2: could not find caller of GetGlyphOutlineA");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.off = 4 * 8; // arg8, address of text

  // Strategy 1: Use caller's address as split
  //hp.type = USING_STRING; // merge different scenario threads

  // Strategy 2: use arg1 as split
  hp.type = USING_STRING|NO_CONTEXT|USING_SPLIT; // merge different scenario threads
  hp.split = 4 * 1; // arg1 as split to get rid of saving message

  // Strategy 3: merge all threads
  //hp.type = USING_STRING|NO_CONTEXT|FIXING_SPLIT; // merge different scenario threads

  ConsoleOutput("vnreng: INSERT WillPlus2");
  NewHook(hp, L"WillPlus2");
  return true;
}
#endif // 0

static void SpecialHookWillPlus(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  //static DWORD detect_offset; // jichi 1/18/2015: this makes sure it only runs once
  //if (detect_offset)
  //  return;
  DWORD i,l;
  union {
    DWORD retn;
    WORD *pw;
    BYTE *pb;
  };
  retn = *(DWORD *)esp_base; // jichi 1/18/2015: dynamically find function return address
  i = 0;
  while (*pw != 0xc483) { //add esp, $
    l = ::disasm(pb);
    if (++i == 5)
      //ConsoleOutput("Fail to detect offset.");
      break;
    retn += l;
  }
  // jichi 2/11/2015: Check baddaddr which might crash the game on Windows XP.
  if (*pw == 0xc483 && !::IsBadReadPtr((LPCVOID)(pb + 2), 1) && !::IsBadReadPtr((LPCVOID)(*(pb + 2) - 8), 1)) {
    ConsoleOutput("vnreng: WillPlus1 pattern found");
    // jichi 1/18/2015:
    // By studying [honeybee] RE:BIRTHDAY SONG, it seems the scenario text is at fixed address
    // This offset might be used to find fixed address
    // However, this method cannot extract character name like GetGlyphOutlineA
    hp->off = *(pb + 2) - 8;

    // Still extract the first text
    //hp->type ^= EXTERN_HOOK;
    char *str = *(char **)(esp_base + hp->off);
    *data = (DWORD)str;
    *len = ::strlen(str);
    *split = 0; // 8/3/2014 jichi: use return address as split

  } else { // jichi 1/19/2015: Try willplus2
    ConsoleOutput("vnreng: WillPlus1 pattern not found, try WillPlus2 instead");
    hp->off = 4 * 8; // arg8, address of text
    hp->type = USING_STRING|NO_CONTEXT|USING_SPLIT; // merge different scenario threads
    hp->split = 4 * 1; // arg1 as split to get rid of saving message
    // The first text is skipped here
    //char *str = *(char **)(esp_base + hp->off);
    //*data = (DWORD)str;
    //*len = ::strlen(str);
  }
  hp->text_fun = nullptr; // stop using text_fun any more
  //detect_offset = 1;
}

// Although the new hook also works for the old game, the old hook is still used by default for compatibility
bool InsertWillPlusHook()
{
  //__debugbreak();
  enum { sub_esp = 0xec81 }; // jichi: caller pattern: sub esp = 0x81,0xec byte
  ULONG addr = MemDbg::findCallerAddress((ULONG)::GetGlyphOutlineA, sub_esp, module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:WillPlus: function call not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.text_fun = SpecialHookWillPlus;
  hp.type = USING_STRING;
  ConsoleOutput("vnreng: INSERT WillPlus");
  NewHook(hp, L"WillPlus");
  //RegisterEngineType(ENGINE_WILLPLUS);
  return true;
}

/** jichi 9/14/2013
 *  TanukiSoft (*.tac)
 *
 *  Seems to be broken for new games in 2012 such like となりの
 *
 *  微少女: /HSN4@004983E0
 *  This is the same hook as ITH
 *  - addr: 4817888 (0x4983e0)
 *  - text_fun: 0x0
 *  - off: 4
 *  - type: 1025 (0x401)
 *
 *  隣りのぷ～さん: /HSN-8@200FE7:TONARINO.EXE
 *  - addr: 2101223 (0x200fe7)
 *  - module: 2343491905 (0x8baed941)
 *  - off: 4294967284 = 0xfffffff4 = -0xc
 *  - type: 1089 (0x441)
 */
bool InsertTanukiHook()
{
  ConsoleOutput("vnreng: trying TanukiSoft");
  for (DWORD i = module_base_; i < module_limit_ - 4; i++)
    if (*(DWORD *)i == 0x8140)
      if (DWORD j = SafeFindEntryAligned(i, 0x400)) { // jichi 9/14/2013: might crash the game without admin priv
        //ITH_GROWL_DWORD2(i, j);
        HookParam hp = {};
        hp.addr = j;
        hp.off = 4;
        hp.type = USING_STRING | NO_CONTEXT;
        ConsoleOutput("vnreng: INSERT TanukiSoft");
        NewHook(hp, L"TanukiSoft");
        return true;
      }

  //ConsoleOutput("Unknown TanukiSoft engine.");
  ConsoleOutput("vnreng:TanukiSoft: failed");
  return false;
}
static void SpecialHookRyokucha(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  const DWORD *base = (const DWORD *)esp_base;
  for (DWORD i = 1; i < 5; i++) {
    DWORD j = base[i];
    if ((j >> 16) == 0 && (j >> 8)) {
      hp->off = i << 2;
      *data = j;
      *len = 2;
      //hp->type &= ~EXTERN_HOOK;
      hp->text_fun = nullptr;
      return;
    }
  }
  *len = 0;
}
bool InsertRyokuchaDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
{
  if (addr != ::GetGlyphOutlineA)
    return false;
  bool flag;
  DWORD insert_addr;
  __asm
  {
    mov eax,fs:[0]
    mov eax,[eax]
    mov eax,[eax] //Step up SEH chain for 2 nodes.
    mov ecx,[eax + 0xC]
    mov eax,[eax + 4]
    add ecx,[ecx - 4]
    mov insert_addr,ecx
    cmp eax,[ecx + 3]
    sete al
    mov flag,al
  }
  if (flag) {
    HookParam hp = {};
    hp.addr = insert_addr;
    hp.length_offset = 1;
    hp.text_fun = SpecialHookRyokucha;
    hp.type = BIG_ENDIAN;
    ConsoleOutput("vnreng: INSERT StudioRyokucha");
    NewHook(hp, L"StudioRyokucha");
    return true;
  }
  //else ConsoleOutput("Unknown Ryokucha engine.");
  ConsoleOutput("vnreng:StudioRyokucha: failed");
  return true;
}
void InsertRyokuchaHook()
{
  //ConsoleOutput("Probably Ryokucha. Wait for text.");
  trigger_fun_ = InsertRyokuchaDynamicHook;
  SwitchTrigger(true);
  ConsoleOutput("vnreng: TRIGGER Ryokucha");
}

/**
 *  jichi 5/11/2014: Hook to the beginning of a function
 *
 *  Here's an example of Demonion II (reladdr = 0x18c540):
 *  The text is displayed character by character.
 *  sub_58C540 proc near
 *  arg_0 = dword ptr  8 // LPCSTR with 1 character
 *
 *  It's weird that I cannot find the caller of this function using OllyDbg.
 *
 *  0138C540  /$ 55             PUSH EBP
 *  0138C541  |. 8BEC           MOV EBP,ESP
 *  0138C543  |. 83E4 F8        AND ESP,0xFFFFFFF8
 *  0138C546  |. 8B43 0C        MOV EAX,DWORD PTR DS:[EBX+0xC]
 *  0138C549  |. 83EC 08        SUB ESP,0x8
 *  0138C54C  |. 56             PUSH ESI
 *  0138C54D  |. 57             PUSH EDI
 *  0138C54E  |. 85C0           TEST EAX,EAX
 *  0138C550  |. 75 04          JNZ SHORT demonion.0138C556
 *  0138C552  |. 33F6           XOR ESI,ESI
 *  0138C554  |. EB 18          JMP SHORT demonion.0138C56E
 *  0138C556  |> 8B4B 14        MOV ECX,DWORD PTR DS:[EBX+0x14]
 *  0138C559  |. 2BC8           SUB ECX,EAX
 *  0138C55B  |. B8 93244992    MOV EAX,0x92492493
 *  0138C560  |. F7E9           IMUL ECX
 *  0138C562  |. 03D1           ADD EDX,ECX
 *  0138C564  |. C1FA 04        SAR EDX,0x4
 *  0138C567  |. 8BF2           MOV ESI,EDX
 *  0138C569  |. C1EE 1F        SHR ESI,0x1F
 *  0138C56C  |. 03F2           ADD ESI,EDX
 *  0138C56E  |> 8B7B 10        MOV EDI,DWORD PTR DS:[EBX+0x10]
 *  0138C571  |. 8BCF           MOV ECX,EDI
 *  0138C573  |. 2B4B 0C        SUB ECX,DWORD PTR DS:[EBX+0xC]
 *  0138C576  |. B8 93244992    MOV EAX,0x92492493
 *  0138C57B  |. F7E9           IMUL ECX
 *  0138C57D  |. 03D1           ADD EDX,ECX
 *  0138C57F  |. C1FA 04        SAR EDX,0x4
 *  0138C582  |. 8BC2           MOV EAX,EDX
 *  0138C584  |. C1E8 1F        SHR EAX,0x1F
 *  0138C587  |. 03C2           ADD EAX,EDX
 *  0138C589  |. 3BC6           CMP EAX,ESI
 *  0138C58B  |. 73 2F          JNB SHORT demonion.0138C5BC
 *  0138C58D  |. C64424 08 00   MOV BYTE PTR SS:[ESP+0x8],0x0
 *  0138C592  |. 8B4C24 08      MOV ECX,DWORD PTR SS:[ESP+0x8]
 *  0138C596  |. 8B5424 08      MOV EDX,DWORD PTR SS:[ESP+0x8]
 *  0138C59A  |. 51             PUSH ECX
 *  0138C59B  |. 8B4D 08        MOV ECX,DWORD PTR SS:[EBP+0x8]
 *  0138C59E  |. 52             PUSH EDX
 *  0138C59F  |. B8 01000000    MOV EAX,0x1
 *  0138C5A4  |. 8BD7           MOV EDX,EDI
 *  0138C5A6  |. E8 F50E0000    CALL demonion.0138D4A0
 *  0138C5AB  |. 83C4 08        ADD ESP,0x8
 *  0138C5AE  |. 83C7 1C        ADD EDI,0x1C
 *  0138C5B1  |. 897B 10        MOV DWORD PTR DS:[EBX+0x10],EDI
 *  0138C5B4  |. 5F             POP EDI
 *  0138C5B5  |. 5E             POP ESI
 *  0138C5B6  |. 8BE5           MOV ESP,EBP
 *  0138C5B8  |. 5D             POP EBP
 *  0138C5B9  |. C2 0400        RETN 0x4
 *  0138C5BC  |> 397B 0C        CMP DWORD PTR DS:[EBX+0xC],EDI
 *  0138C5BF  |. 76 05          JBE SHORT demonion.0138C5C6
 *  0138C5C1  |. E8 1B060D00    CALL demonion.0145CBE1
 *  0138C5C6  |> 8B03           MOV EAX,DWORD PTR DS:[EBX]
 *  0138C5C8  |. 57             PUSH EDI                                 ; /Arg4
 *  0138C5C9  |. 50             PUSH EAX                                 ; |Arg3
 *  0138C5CA  |. 8B45 08        MOV EAX,DWORD PTR SS:[EBP+0x8]           ; |
 *  0138C5CD  |. 50             PUSH EAX                                 ; |Arg2
 *  0138C5CE  |. 8D4C24 14      LEA ECX,DWORD PTR SS:[ESP+0x14]          ; |
 *  0138C5D2  |. 51             PUSH ECX                                 ; |Arg1
 *  0138C5D3  |. 8BC3           MOV EAX,EBX                              ; |
 *  0138C5D5  |. E8 D6010000    CALL demonion.0138C7B0                   ; \demonion.0138C7B0
 *  0138C5DA  |. 5F             POP EDI
 *  0138C5DB  |. 5E             POP ESI
 *  0138C5DC  |. 8BE5           MOV ESP,EBP
 *  0138C5DE  |. 5D             POP EBP
 *  0138C5DF  \. C2 0400        RETN 0x4
 */
bool InsertGXPHook()
{
  union {
    DWORD i;
    DWORD *id;
    BYTE *ib;
  };
  //__asm int 3
  for (i = module_base_ + 0x1000; i < module_limit_ - 4; i++) {
    //find cmp word ptr [esi*2+eax],0
    if (*id != 0x703c8366)
      continue;
    i += 4;
    if (*ib != 0)
      continue;
    i++;
    DWORD j = i + 0x200;
    j = j < (module_limit_ - 8) ? j : (module_limit_ - 8);

    DWORD flag = false;
    while (i < j) {
      DWORD k = disasm(ib);
      if (k == 0)
        break;
      if (k == 1 && (*ib & 0xf8) == 0x50) { // push reg
        flag = true;
        break;
      }
      i += k;
    }
    if (flag)
      while (i < j) {
        if (*ib == 0xe8) {
          i++;
          DWORD addr = *id + i + 4;
          if (addr > module_base_ && addr < module_limit_) {
            HookParam hp = {};
            hp.addr = addr;
            hp.type = USING_UNICODE | DATA_INDIRECT;
            hp.length_offset = 1;
            hp.off = 4;

            //ITH_GROWL_DWORD3(hp.addr, module_base_, hp.addr - module_base_);
            //DWORD call = Util::FindCallAndEntryAbs(hp.addr, module_limit_ - module_base_, module_base_, 0xec81); // zero
            //DWORD call = Util::FindCallAndEntryAbs(hp.addr, module_limit_ - module_base_, module_base_, 0xec83); // zero
            //DWORD call = Util::FindCallAndEntryAbs(hp.addr, module_limit_ - module_base_, module_base_, 0xec8b55); // zero
            //ITH_GROWL_DWORD3(call, module_base_, call - module_base_);

            ConsoleOutput("vnreng: INSERT GXP");
            NewHook(hp, L"GXP");
            return true;
          }
        }
        i++;
      }
  }
  //ConsoleOutput("Unknown GXP engine.");
  ConsoleOutput("vnreng:GXP: failed");
  return false;
}

namespace { // unnamed, for Anex86
BYTE JIS_tableH[0x80] = {
  0x00,0x81,0x81,0x82,0x82,0x83,0x83,0x84,
  0x84,0x85,0x85,0x86,0x86,0x87,0x87,0x88,
  0x88,0x89,0x89,0x8a,0x8a,0x8b,0x8b,0x8c,
  0x8c,0x8d,0x8d,0x8e,0x8e,0x8f,0x8f,0x90,
  0x90,0x91,0x91,0x92,0x92,0x93,0x93,0x94,
  0x94,0x95,0x95,0x96,0x96,0x97,0x97,0x98,
  0x98,0x99,0x99,0x9a,0x9a,0x9b,0x9b,0x9c,
  0x9c,0x9d,0x9d,0x9e,0x9e,0xdf,0xdf,0xe0,
  0xe0,0xe1,0xe1,0xe2,0xe2,0xe3,0xe3,0xe4,
  0xe4,0xe5,0xe5,0xe6,0xe6,0xe7,0xe7,0xe8,
  0xe8,0xe9,0xe9,0xea,0xea,0xeb,0xeb,0xec,
  0xec,0xed,0xed,0xee,0xee,0xef,0xef,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

BYTE JIS_tableL[0x80] = {
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,
  0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,
  0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,
  0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,
  0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,
  0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,
  0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,
  0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,
  0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
  0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
  0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
  0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x00,
};

void SpecialHookAnex86(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  __asm
  {
    mov eax, esp_base
    mov ecx, [eax - 0xC]
    cmp byte ptr [ecx + 0xE], 0
    jnz _fin
    movzx ebx, byte ptr [ecx + 0xC] ; Low byte
    movzx edx, byte ptr [ecx + 0xD] ; High byte
    test edx,edx
    jnz _jis_char
    mov eax,data
    mov [eax],ebx
    mov eax, len
    mov [eax], 1
    jmp _fin
_jis_char:
    cmp ebx,0x7E
    ja _fin
    cmp edx,0x7E
    ja _fin
    test dl,1
    lea eax, [ebx + 0x7E]
    movzx ecx, byte ptr [JIS_tableL + ebx]
    cmovnz eax, ecx
    mov ah, byte ptr [JIS_tableH + edx]
    ror ax,8
    mov ecx, data
    mov [ecx], eax
    mov ecx, len
    mov [ecx], 2
_fin:
  }

}
} // unnamed namespace
bool InsertAnex86Hook()
{
  const DWORD dwords[] = {0x618ac033,0x0d418a0c}; // jichi 12/25/2013: Remove static keyword
  for (DWORD i = module_base_ + 0x1000; i < module_limit_ - 8; i++)
    if (*(DWORD *)i == dwords[0])
      if (*(DWORD *)(i + 4) == dwords[1]) {
        HookParam hp = {};
        hp.addr = i;
        hp.text_fun = SpecialHookAnex86;
        //hp.type = EXTERN_HOOK;
        hp.length_offset = 1;
        ConsoleOutput("vnreng: INSERT Anex86");
        NewHook(hp, L"Anex86");
        return true;
      }
  ConsoleOutput("vnreng:Anex86: failed");
  return false;
}
//static char* ShinyDaysQueueString[0x10];
//static int ShinyDaysQueueStringLen[0x10];
//static int ShinyDaysQueueIndex, ShinyDaysQueueNext;
static void SpecialHookShinyDays(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  static int ShinyDaysQueueStringLen;
  LPWSTR fun_str;
  char *text_str;
  DWORD l = 0;
  __asm
  {
    mov eax,esp_base
    mov ecx,[eax+0x4C]
    mov fun_str,ecx
    mov esi,[eax+0x70]
    mov edi,[eax+0x74]
    add esi,0x3C
    cmp esi,edi
    jae _no_text
    mov edx,[esi+0x10]
    mov ecx,esi
    cmp edx,8
    cmovae ecx,[ecx]
    add edx,edx
    mov text_str,ecx
    mov l,edx
_no_text:
  }
  if (::memcmp(fun_str, L"[PlayVoice]",0x18) == 0) {
    *data = (DWORD)text_buffer;
    *len = ShinyDaysQueueStringLen;
  }
  else if (::memcmp(fun_str, L"[PrintText]",0x18) == 0) {
    memcpy(text_buffer, text_str, l);
    ShinyDaysQueueStringLen = l;
  }
}
bool InsertShinyDaysHook()
{
  const BYTE bytes[] = {
    0xff,0x83,0x70,0x03,0x00,0x00,0x33,0xf6,
    0xc6,0x84,0x24,0x90,0x02,0x00,0x00,0x02
  };
  LPVOID addr = (LPVOID)0x42ad94;
  if (::memcmp(addr, bytes, sizeof(bytes)) != 0) {
    ConsoleOutput("vnreng:ShinyDays: only work for 1.00");
    return false;
  }

  HookParam hp = {};
  hp.addr = 0x42ad9c;
  hp.text_fun = SpecialHookShinyDays;
  hp.type = USING_UNICODE|USING_STRING|NO_CONTEXT;
  ConsoleOutput("vnreng: INSERT ShinyDays");
  NewHook(hp, L"ShinyDays 1.00");
  return true;
}

/**
 *  jichi 9/5/2013: NEXTON games with aInfo.db
 *  Sample games:
 *  - /HA-C@4D69E:InnocentBullet.exe (イノセントバレット)
 *  - /HA-C@40414C:ImoutoBancho.exe (妹番長)
 *
 *  See: http://ja.wikipedia.org/wiki/ネクストン
 *  See (CaoNiMaGeBi): http://tieba.baidu.com/p/2576241908
 *
 *  Old:
 *  md5 = 85ac031f2539e1827d9a1d9fbde4023d
 *  hcode = /HA-C@40414C:ImoutoBancho.exe
 *  - addr: 4211020 (0x40414c)
 *  - module: 1051997988 (0x3eb43724)
 *  - length_offset: 1
 *  - off: 4294967280 (0xfffffff0) = -0x10
 *  - split: 0
 *  - type: 68 (0x44)
 *
 *  New (11/7/2013):
 *  /HA-20:4@583DE:MN2.EXE (NEW)
 *  - addr: 361438 (0x583de)
 *  - module: 3436540819
 *  - length_offset: 1
 *  - off: 4294967260 (0xffffffdc) = -0x24
 *  - split: 4
 *  - type: 84 (0x54)
 */

bool InsertNextonHook()
{
  // 0x8944241885c00f84
  const BYTE bytes[] = {
    //0xe8 //??,??,??,??,      00804147   e8 24d90100      call imoutoba.00821a70
    0x89,0x44,0x24, 0x18,   // 0080414c   894424 18        mov dword ptr ss:[esp+0x18],eax; hook here
    0x85,0xc0,              // 00804150   85c0             test eax,eax
    0x0f,0x84               // 00804152  ^0f84 c0feffff    je imoutoba.00804018
  };
  //enum { hook_offset = 0 };
  ULONG addr = module_base_; //- sizeof(bytes);
  do {
    addr += sizeof(bytes); // ++ so that each time return diff address
    ULONG range = min(module_limit_ - addr, MAX_REL_ADDR);
    addr = MemDbg::findBytes(bytes, sizeof(bytes), addr, addr + range);
    if (!addr) {
      ConsoleOutput("vnreng:NEXTON: pattern not exist");
      return false;
    }

    //const BYTE hook_ins[] = {
    //  0x57,       // 00804144   57               push edi
    //  0x8b,0xc3,  // 00804145   8bc3             mov eax,ebx
    //  0xe8 //??,??,??,??,      00804147   e8 24d90100      call imoutoba.00821a70
    //};
  } while(0xe8c38b57 != *(DWORD *)(addr - 8));

  //ITH_GROWL_DWORD3(module_base_, addr, *(DWORD *)(addr-8));

  HookParam hp = {};
  hp.addr = addr;
  hp.length_offset = 1;
  //hp.off = -0x10;
  //hp.type = BIG_ENDIAN; // 4

  // 魔王のくせに生イキだっ！2 ～今度は性戦だ！～
  // CheatEngine search for byte array: 8944241885C00F84
  //addr = 0x4583de; // wrong
  //addr = 0x5460ba;
  //addr = 0x5f3d8a;
  //addr = 0x768776;
  //addr = 0x7a5319;

  hp.off = -0x24;
  hp.split = 4;
  hp.type = BIG_ENDIAN|USING_SPLIT; // 0x54

  // Indirect is needed for new games,
  // Such as: /HA-C*0@4583DE for 「魔王のくせに生イキだっ！２」
  //hp.type = BIG_ENDIAN|DATA_INDIRECT; // 12
  //hp.type = USING_UNICODE;
  //ITH_GROWL_DWORD3(addr, -hp.off, hp.type);

  ConsoleOutput("vnreng: INSERT NEXTON");
  NewHook(hp, L"NEXTON");

  //ConsoleOutput("NEXTON");
  return true;
}

/** jichi 8/17/2014 Nexton1
 *  Sample games:
 *  - [Nomad][071026] 淫烙の巫女 Trial
 *
 *  Debug method: text are prefetched into memory. Add break point to it.
 *
 *  GetGlyphOutlineA is called, but no correct text.
 *
 *  There are so many good hooks. The shortest function was picked,as follows:
 *  0041974e   cc               int3
 *  0041974f   cc               int3
 *  00419750   56               push esi    ; jichi: hook here, text in arg1
 *  00419751   8b7424 08        mov esi,dword ptr ss:[esp+0x8]
 *  00419755   8bc6             mov eax,esi
 *  00419757   57               push edi
 *  00419758   8d78 01          lea edi,dword ptr ds:[eax+0x1]
 *  0041975b   eb 03            jmp short inrakutr.00419760
 *  0041975d   8d49 00          lea ecx,dword ptr ds:[ecx]
 *  00419760   8a10             mov dl,byte ptr ds:[eax] ; jichi: eax is the text
 *  00419762   83c0 01          add eax,0x1
 *  00419765   84d2             test dl,dl
 *  00419767  ^75 f7            jnz short inrakutr.00419760
 *  00419769   2bc7             sub eax,edi
 *  0041976b   50               push eax
 *  0041976c   56               push esi
 *  0041976d   83c1 04          add ecx,0x4
 *  00419770   e8 eb85feff      call inrakutr.00401d60
 *  00419775   5f               pop edi
 *  00419776   5e               pop esi
 *  00419777   c2 0400          retn 0x4
 *  0041977a   cc               int3
 *  0041977b   cc               int3
 *  0041977c   cc               int3
 *
 *  Runtime stack: this function takes two arguments. Text address is in arg1.
 *
 *  Other possible hooks are as follows:
 *  00460caf   53               push ebx
 *  00460cb0   c700 16000000    mov dword ptr ds:[eax],0x16
 *  00460cb6   e8 39feffff      call inrakutr.00460af4
 *  00460cbb   83c4 14          add esp,0x14
 *  00460cbe   385d fc          cmp byte ptr ss:[ebp-0x4],bl
 *  00460cc1   74 07            je short inrakutr.00460cca
 *  00460cc3   8b45 f8          mov eax,dword ptr ss:[ebp-0x8]
 *  00460cc6   8360 70 fd       and dword ptr ds:[eax+0x70],0xfffffffd
 *  00460cca   33c0             xor eax,eax
 *  00460ccc   eb 2c            jmp short inrakutr.00460cfa
 *  00460cce   0fb601           movzx eax,byte ptr ds:[ecx] ; jichi: here, ecx
 *  00460cd1   8b55 f4          mov edx,dword ptr ss:[ebp-0xc]
 *  00460cd4   f64410 1d 04     test byte ptr ds:[eax+edx+0x1d],0x4
 *  00460cd9   74 0e            je short inrakutr.00460ce9
 *  00460cdb   8d51 01          lea edx,dword ptr ds:[ecx+0x1]
 *  00460cde   381a             cmp byte ptr ds:[edx],bl
 *  00460ce0   74 07            je short inrakutr.00460ce9
 *  00460ce2   c1e0 08          shl eax,0x8
 *  00460ce5   8bf0             mov esi,eax
 *  00460ce7   8bca             mov ecx,edx
 *  00460ce9   0fb601           movzx eax,byte ptr ds:[ecx]
 *  00460cec   03c6             add eax,esi
 *  00460cee   385d fc          cmp byte ptr ss:[ebp-0x4],bl
 *  00460cf1   74 07            je short inrakutr.00460cfa
 *  00460cf3   8b4d f8          mov ecx,dword ptr ss:[ebp-0x8]
 *  00460cf6   8361 70 fd       and dword ptr ds:[ecx+0x70],0xfffffffd
 *  00460cfa   5e               pop esi
 *  00460cfb   5b               pop ebx
 *  00460cfc   c9               leave
 *  00460cfd   c3               retn
 *
 *  00460d41   74 05            je short inrakutr.00460d48
 *  00460d43   381e             cmp byte ptr ds:[esi],bl
 *  00460d45   74 01            je short inrakutr.00460d48
 *  00460d47   46               inc esi
 *  00460d48   8bc6             mov eax,esi
 *  00460d4a   5e               pop esi
 *  00460d4b   5b               pop ebx
 *  00460d4c   c3               retn
 *  00460d4d   56               push esi
 *  00460d4e   8b7424 08        mov esi,dword ptr ss:[esp+0x8]
 *  00460d52   0fb606           movzx eax,byte ptr ds:[esi] ; jichi: esi & ebp
 *  00460d55   50               push eax
 *  00460d56   e8 80fcffff      call inrakutr.004609db
 *  00460d5b   85c0             test eax,eax
 *  00460d5d   59               pop ecx
 *  00460d5e   74 0b            je short inrakutr.00460d6b
 *  00460d60   807e 01 00       cmp byte ptr ds:[esi+0x1],0x0
 *  00460d64   74 05            je short inrakutr.00460d6b
 *  00460d66   6a 02            push 0x2
 *  00460d68   58               pop eax
 *  00460d69   5e               pop esi
 *  00460d6a   c3               retn
 *
 *  00460d1d   53               push ebx
 *  00460d1e   53               push ebx
 *  00460d1f   53               push ebx
 *  00460d20   53               push ebx
 *  00460d21   53               push ebx
 *  00460d22   c700 16000000    mov dword ptr ds:[eax],0x16
 *  00460d28   e8 c7fdffff      call inrakutr.00460af4
 *  00460d2d   83c4 14          add esp,0x14
 *  00460d30   33c0             xor eax,eax
 *  00460d32   eb 16            jmp short inrakutr.00460d4a
 *  00460d34   0fb606           movzx eax,byte ptr ds:[esi] ; jichi: esi, ebp
 *  00460d37   50               push eax
 *  00460d38   e8 9efcffff      call inrakutr.004609db
 *  00460d3d   46               inc esi
 *  00460d3e   85c0             test eax,eax
 *  00460d40   59               pop ecx
 *  00460d41   74 05            je short inrakutr.00460d48
 *  00460d43   381e             cmp byte ptr ds:[esi],bl
 *  00460d45   74 01            je short inrakutr.00460d48
 *  00460d47   46               inc esi
 *
 *  0042c59f   cc               int3
 *  0042c5a0   56               push esi
 *  0042c5a1   8bf1             mov esi,ecx
 *  0042c5a3   8b86 cc650000    mov eax,dword ptr ds:[esi+0x65cc]
 *  0042c5a9   8b50 1c          mov edx,dword ptr ds:[eax+0x1c]
 *  0042c5ac   57               push edi
 *  0042c5ad   8b7c24 0c        mov edi,dword ptr ss:[esp+0xc]
 *  0042c5b1   8d8e cc650000    lea ecx,dword ptr ds:[esi+0x65cc]
 *  0042c5b7   57               push edi
 *  0042c5b8   ffd2             call edx
 *  0042c5ba   8bc7             mov eax,edi
 *  0042c5bc   8d50 01          lea edx,dword ptr ds:[eax+0x1]
 *  0042c5bf   90               nop
 *  0042c5c0   8a08             mov cl,byte ptr ds:[eax] ; jichi: here eax
 *  0042c5c2   83c0 01          add eax,0x1
 *  0042c5c5   84c9             test cl,cl
 *  0042c5c7  ^75 f7            jnz short inrakutr.0042c5c0
 *  0042c5c9   2bc2             sub eax,edx
 *  0042c5cb   50               push eax
 *  0042c5cc   57               push edi
 *  0042c5cd   8d8e 24660000    lea ecx,dword ptr ds:[esi+0x6624]
 *  0042c5d3   e8 8857fdff      call inrakutr.00401d60
 *  0042c5d8   8b86 b4660000    mov eax,dword ptr ds:[esi+0x66b4]
 *  0042c5de   85c0             test eax,eax
 *  0042c5e0   74 0d            je short inrakutr.0042c5ef
 *  0042c5e2   8b8e b8660000    mov ecx,dword ptr ds:[esi+0x66b8]
 *  0042c5e8   2bc8             sub ecx,eax
 *  0042c5ea   c1f9 02          sar ecx,0x2
 *  0042c5ed   75 05            jnz short inrakutr.0042c5f4
 *  0042c5ef   e8 24450300      call inrakutr.00460b18
 *  0042c5f4   8b96 b4660000    mov edx,dword ptr ds:[esi+0x66b4]
 *  0042c5fa   8b0a             mov ecx,dword ptr ds:[edx]
 *  0042c5fc   8b01             mov eax,dword ptr ds:[ecx]
 *  0042c5fe   8b50 30          mov edx,dword ptr ds:[eax+0x30]
 *  0042c601   ffd2             call edx
 *  0042c603   8b06             mov eax,dword ptr ds:[esi]
 *  0042c605   8b90 f8000000    mov edx,dword ptr ds:[eax+0xf8]
 *  0042c60b   6a 00            push 0x0
 *  0042c60d   68 c3164a00      push inrakutr.004a16c3
 *  0042c612   57               push edi
 *  0042c613   8bce             mov ecx,esi
 *  0042c615   ffd2             call edx
 *  0042c617   5f               pop edi
 *  0042c618   5e               pop esi
 *  0042c619   c2 0400          retn 0x4
 *  0042c61c   cc               int3
 *
 *  0041974e   cc               int3
 *  0041974f   cc               int3
 *  00419750   56               push esi
 *  00419751   8b7424 08        mov esi,dword ptr ss:[esp+0x8]
 *  00419755   8bc6             mov eax,esi
 *  00419757   57               push edi
 *  00419758   8d78 01          lea edi,dword ptr ds:[eax+0x1]
 *  0041975b   eb 03            jmp short inrakutr.00419760
 *  0041975d   8d49 00          lea ecx,dword ptr ds:[ecx]
 *  00419760   8a10             mov dl,byte ptr ds:[eax] ; jichi: eax
 *  00419762   83c0 01          add eax,0x1
 *  00419765   84d2             test dl,dl
 *  00419767  ^75 f7            jnz short inrakutr.00419760
 *  00419769   2bc7             sub eax,edi
 *  0041976b   50               push eax
 *  0041976c   56               push esi
 *  0041976d   83c1 04          add ecx,0x4
 *  00419770   e8 eb85feff      call inrakutr.00401d60
 *  00419775   5f               pop edi
 *  00419776   5e               pop esi
 *  00419777   c2 0400          retn 0x4
 *  0041977a   cc               int3
 *  0041977b   cc               int3
 *  0041977c   cc               int3
 *
 *  0042c731   57               push edi
 *  0042c732   ffd0             call eax
 *  0042c734   8bc7             mov eax,edi
 *  0042c736   8d50 01          lea edx,dword ptr ds:[eax+0x1]
 *  0042c739   8da424 00000000  lea esp,dword ptr ss:[esp]
 *  0042c740   8a08             mov cl,byte ptr ds:[eax] ; jichi: eax
 *  0042c742   83c0 01          add eax,0x1
 *  0042c745   84c9             test cl,cl
 *  0042c747  ^75 f7            jnz short inrakutr.0042c740
 *  0042c749   2bc2             sub eax,edx
 *  0042c74b   8bf8             mov edi,eax
 *  0042c74d   e8 fe1d0100      call inrakutr.0043e550
 *  0042c752   8b0d 187f4c00    mov ecx,dword ptr ds:[0x4c7f18]
 *  0042c758   8b11             mov edx,dword ptr ds:[ecx]
 *  0042c75a   8b42 70          mov eax,dword ptr ds:[edx+0x70]
 *  0042c75d   ffd0             call eax
 *  0042c75f   83c0 0a          add eax,0xa
 *  0042c762   0fafc7           imul eax,edi
 *  0042c765   5f               pop edi
 *  0042c766   8986 60660000    mov dword ptr ds:[esi+0x6660],eax
 */
bool InsertNexton1Hook()
{
  // Use accurate stopAddress in case of running out of memory
  // Since the file pattern for Nexton1 is not accurate.
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) {
    ConsoleOutput("vnreng:NEXTON1: failed to get memory range");
    return false;
  }
  const BYTE bytes[] = {
    0x56,                  // 00419750   56               push esi    ; jichi: hook here, text in arg1
    0x8b,0x74,0x24, 0x08,  // 00419751   8b7424 08        mov esi,dword ptr ss:[esp+0x8]
    0x8b,0xc6,             // 00419755   8bc6             mov eax,esi
    0x57,                  // 00419757   57               push edi
    0x8d,0x78, 0x01,       // 00419758   8d78 01          lea edi,dword ptr ds:[eax+0x1]
    0xeb, 0x03,            // 0041975b   eb 03            jmp short inrakutr.00419760
    0x8d,0x49, 0x00,       // 0041975d   8d49 00          lea ecx,dword ptr ds:[ecx]
    0x8a,0x10,             // 00419760   8a10             mov dl,byte ptr ds:[eax] ; jichi: eax is the text
    0x83,0xc0, 0x01,       // 00419762   83c0 01          add eax,0x1
    0x84,0xd2,             // 00419765   84d2             test dl,dl
    0x75, 0xf7,            // 00419767  ^75 f7            jnz short inrakutr.00419760
    0x2b,0xc7,             // 00419769   2bc7             sub eax,edi
    0x50,                  // 0041976b   50               push eax
    0x56,                  // 0041976c   56               push esi
    0x83,0xc1, 0x04        // 0041976d   83c1 04          add ecx,0x4
    //0xe8, XX4,           // 00419770   e8 eb85feff      call inrakutr.00401d60
    //0x5f,                // 00419775   5f               pop edi
    //0x5e,                // 00419776   5e               pop esi
    //0xc2, 0x04,0x00      // 00419777   c2 0400          retn 0x4
  };
  enum { hook_offset = 0 }; // distance to the beginning of the function
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), startAddress, stopAddress);
  //ITH_GROWL_DWORD(addr); // supposed to be 0x4010e0
  if (!addr) {
    ConsoleOutput("vnreng:NEXTON1: pattern not found");
    return false;
  }
  //ITH_GROWL_DWORD(addr);

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  //hp.length_offset = 1;
  hp.off = 4; // [esp+4] == arg0
  hp.type = USING_STRING;
  ConsoleOutput("vnreng: INSERT NEXTON1");
  NewHook(hp, L"NEXTON1");
  return true;
}

/**
 *  jichi 9/16/2013: a-unicorn / gesen18
 *  See (CaoNiMaGeBi): http://tieba.baidu.com/p/2586681823
 *  Pattern: 2bce8bf8
 *      2bce      sub ecx,esi ; hook here
 *      8bf8      mov eds,eax
 *      8bd1      mov edx,ecx
 *
 *  /HBN-20*0@xxoo
 *  - length_offset: 1
 *  - off: 4294967260 (0xffffffdc)
 *  - type: 1032 (0x408)
 */
bool InsertGesen18Hook()
{
  const BYTE bytes[] = {
    0x2b,0xce,  // sub ecx,esi ; hook here
    0x8b,0xf8   // mov eds,eax
  };
  //enum { hook_offset = 0 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!addr) {
    ConsoleOutput("vnreng:Gesen18: pattern not exist");
    return false;
  }

  HookParam hp = {};
  hp.type = NO_CONTEXT | DATA_INDIRECT;
  hp.length_offset = 1;
  hp.off = -0x24;
  hp.addr = addr;

  //index = SearchPattern(module_base_, size,ins, sizeof(ins));
  //ITH_GROWL_DWORD2(base, index);

  ConsoleOutput("vnreng: INSERT Gesen18");
  NewHook(hp, L"Gesen18");
  //ConsoleOutput("Gesen18");
  return true;
}

/**
 *  jichi 10/1/2013: Artemis Engine
 *  See: http://www.ies-net.com/
 *  See (CaoNiMaGeBi): http://tieba.baidu.com/p/2625537737
 *  Pattern:
 *     650a2f 83c4 0c   add esp,0xc ; hook here
 *     650a32 0fb6c0    movzx eax,al
 *     650a35 85c0      test eax,eax
 *     0fb6c0 75 0e     jnz short tsugokaz.0065a47
 *
 *  Wrong: 0x400000 + 0x7c574
 *
 *  //Example: [130927]妹スパイラル /HBN-8*0:14@65589F
 *  Example: ツゴウノイイ家族 Trial /HBN-8*0:14@650A2F
 *  Note: 0x650a2f > 40000(base) + 20000(limit)
 *  - addr: 0x650a2f
 *  - text_fun: 0x0
 *  - function: 0
 *  - hook_len: 0
 *  - ind: 0
 *  - length_offset: 1
 *  - module: 0
 *  - off: 4294967284 = 0xfffffff4 = -0xc
 *  - recover_len: 0
 *  - split: 20 = 0x14
 *  - split_ind: 0
 *  - type: 1048 = 0x418
 *
 *  @CaoNiMaGeBi:
 *  RECENT GAMES:
 *    [130927]妹スパイラル /HBN-8*0:14@65589F
 *    [130927]サムライホルモン
 *    [131025]ツゴウノイイ家族 /HBN-8*0:14@650A2F (for trial version)
 *    CLIENT ORGANIZAIONS:
 *    CROWD
 *    D:drive.
 *    Hands-Aid Corporation
 *    iMel株式会社
 *    SHANNON
 *    SkyFish
 *    SNACK-FACTORY
 *    team flap
 *    Zodiac
 *    くらむちゃうだ～
 *    まかろんソフト
 *    アイディアファクトリー株式会社
 *    カラクリズム
 *    合资会社ファーストリーム
 *    有限会社ウルクスへブン
 *    有限会社ロータス
 *    株式会社CUCURI
 *    株式会社アバン
 *    株式会社インタラクティブブレインズ
 *    株式会社ウィンディール
 *    株式会社エヴァンジェ
 *    株式会社ポニーキャニオン
 *    株式会社大福エンターテインメント
 */
bool InsertArtemisHook()
{
  const BYTE bytes[] = {
    0x83,0xc4, 0x0c, // add esp,0xc ; hook here
    0x0f,0xb6,0xc0,  // movzx eax,al
    0x85,0xc0,       // test eax,eax
    0x75, 0x0e       // jnz XXOO ; it must be 0xe, or there will be duplication
  };
  //enum { hook_offset = 0 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD3(reladdr, module_base_, range);
  if (!addr) {
    ConsoleOutput("vnreng:Artemis: pattern not exist");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.length_offset = 1;
  hp.off = -0xc;
  hp.split = 0x14;
  hp.type = NO_CONTEXT|DATA_INDIRECT|USING_SPLIT; // 0x418

  //hp.addr = 0x650a2f;
  //ITH_GROWL_DWORD(hp.addr);

  ConsoleOutput("vnreng: INSERT Artemis");
  NewHook(hp, L"Artemis");
  //ConsoleOutput("Artemis");
  return true;
}

/**
 *  jichi 1/2/2014: Taskforce2 Engine
 *
 *  Examples:
 *  神様(仮)-カミサマカッコカリ- 路地裏繚乱編 (1.1)
 *  /HS-8@178872:Taskforce2.exe
 *
 *  00578819   . 50             push eax                                 ; |arg1
 *  0057881a   . c745 f4 cc636b>mov dword ptr ss:[ebp-0xc],taskforc.006b>; |
 *  00578821   . e8 31870000    call taskforc.00580f57                   ; \taskforc.00580f57
 *  00578826   . cc             int3
 *  00578827  /$ 8b4c24 04      mov ecx,dword ptr ss:[esp+0x4]
 *  0057882b  |. 53             push ebx
 *  0057882c  |. 33db           xor ebx,ebx
 *  0057882e  |. 3bcb           cmp ecx,ebx
 *  00578830  |. 56             push esi
 *  00578831  |. 57             push edi
 *  00578832  |. 74 08          je short taskforc.0057883c
 *  00578834  |. 8b7c24 14      mov edi,dword ptr ss:[esp+0x14]
 *  00578838  |. 3bfb           cmp edi,ebx
 *  0057883a  |. 77 1b          ja short taskforc.00578857
 *  0057883c  |> e8 28360000    call taskforc.0057be69
 *  00578841  |. 6a 16          push 0x16
 *  00578843  |. 5e             pop esi
 *  00578844  |. 8930           mov dword ptr ds:[eax],esi
 *  00578846  |> 53             push ebx
 *  00578847  |. 53             push ebx
 *  00578848  |. 53             push ebx
 *  00578849  |. 53             push ebx
 *  0057884a  |. 53             push ebx
 *  0057884b  |. e8 6a050000    call taskforc.00578dba
 *  00578850  |. 83c4 14        add esp,0x14
 *  00578853  |. 8bc6           mov eax,esi
 *  00578855  |. eb 31          jmp short taskforc.00578888
 *  00578857  |> 8b7424 18      mov esi,dword ptr ss:[esp+0x18]
 *  0057885b  |. 3bf3           cmp esi,ebx
 *  0057885d  |. 75 04          jnz short taskforc.00578863
 *  0057885f  |. 8819           mov byte ptr ds:[ecx],bl
 *  00578861  |.^eb d9          jmp short taskforc.0057883c
 *  00578863  |> 8bd1           mov edx,ecx
 *  00578865  |> 8a06           /mov al,byte ptr ds:[esi]
 *  00578867  |. 8802           |mov byte ptr ds:[edx],al
 *  00578869  |. 42             |inc edx
 *  0057886a  |. 46             |inc esi
 *  0057886b  |. 3ac3           |cmp al,bl
 *  0057886d  |. 74 03          |je short taskforc.00578872
 *  0057886f  |. 4f             |dec edi
 *  00578870  |.^75 f3          \jnz short taskforc.00578865
 *  00578872  |> 3bfb           cmp edi,ebx ; jichi: hook here
 *  00578874  |. 75 10          jnz short taskforc.00578886
 *  00578876  |. 8819           mov byte ptr ds:[ecx],bl
 *  00578878  |. e8 ec350000    call taskforc.0057be69
 *  0057887d  |. 6a 22          push 0x22
 *  0057887f  |. 59             pop ecx
 *  00578880  |. 8908           mov dword ptr ds:[eax],ecx
 *  00578882  |. 8bf1           mov esi,ecx
 *  00578884  |.^eb c0          jmp short taskforc.00578846
 *  00578886  |> 33c0           xor eax,eax
 *  00578888  |> 5f             pop edi
 *  00578889  |. 5e             pop esi
 *  0057888a  |. 5b             pop ebx
 *  0057888b  \. c3             retn
 *
 *  [131129] [Digital Cute] オトメスイッチ -OtomeSwitch- ～彼が持ってる彼女のリモコン～ (1.1)
 *  /HS-8@1948E9:Taskforce2.exe
 *  - addr: 0x1948e9
 *  - off: 4294967284 (0xfffffff4 = -0xc)
 *  - type: 65  (0x41)
 *
 *  00594890   . 50             push eax                                 ; |arg1
 *  00594891   . c745 f4 64c56d>mov dword ptr ss:[ebp-0xc],taskforc.006d>; |
 *  00594898   . e8 88880000    call taskforc.0059d125                   ; \taskforc.0059d125
 *  0059489d   . cc             int3
 *  0059489e  /$ 8b4c24 04      mov ecx,dword ptr ss:[esp+0x4]
 *  005948a2  |. 53             push ebx
 *  005948a3  |. 33db           xor ebx,ebx
 *  005948a5  |. 3bcb           cmp ecx,ebx
 *  005948a7  |. 56             push esi
 *  005948a8  |. 57             push edi
 *  005948a9  |. 74 08          je short taskforc.005948b3
 *  005948ab  |. 8b7c24 14      mov edi,dword ptr ss:[esp+0x14]
 *  005948af  |. 3bfb           cmp edi,ebx
 *  005948b1  |. 77 1b          ja short taskforc.005948ce
 *  005948b3  |> e8 91350000    call taskforc.00597e49
 *  005948b8  |. 6a 16          push 0x16
 *  005948ba  |. 5e             pop esi
 *  005948bb  |. 8930           mov dword ptr ds:[eax],esi
 *  005948bd  |> 53             push ebx
 *  005948be  |. 53             push ebx
 *  005948bf  |. 53             push ebx
 *  005948c0  |. 53             push ebx
 *  005948c1  |. 53             push ebx
 *  005948c2  |. e8 7e010000    call taskforc.00594a45
 *  005948c7  |. 83c4 14        add esp,0x14
 *  005948ca  |. 8bc6           mov eax,esi
 *  005948cc  |. eb 31          jmp short taskforc.005948ff
 *  005948ce  |> 8b7424 18      mov esi,dword ptr ss:[esp+0x18]
 *  005948d2  |. 3bf3           cmp esi,ebx
 *  005948d4  |. 75 04          jnz short taskforc.005948da
 *  005948d6  |. 8819           mov byte ptr ds:[ecx],bl
 *  005948d8  |.^eb d9          jmp short taskforc.005948b3
 *  005948da  |> 8bd1           mov edx,ecx
 *  005948dc  |> 8a06           /mov al,byte ptr ds:[esi]
 *  005948de  |. 8802           |mov byte ptr ds:[edx],al
 *  005948e0  |. 42             |inc edx
 *  005948e1  |. 46             |inc esi
 *  005948e2  |. 3ac3           |cmp al,bl
 *  005948e4  |. 74 03          |je short taskforc.005948e9
 *  005948e6  |. 4f             |dec edi
 *  005948e7  |.^75 f3          \jnz short taskforc.005948dc
 *  005948e9  |> 3bfb           cmp edi,ebx ; jichi: hook here
 *  005948eb  |. 75 10          jnz short taskforc.005948fd
 *  005948ed  |. 8819           mov byte ptr ds:[ecx],bl
 *  005948ef  |. e8 55350000    call taskforc.00597e49
 *  005948f4  |. 6a 22          push 0x22
 *  005948f6  |. 59             pop ecx
 *  005948f7  |. 8908           mov dword ptr ds:[eax],ecx
 *  005948f9  |. 8bf1           mov esi,ecx
 *  005948fb  |.^eb c0          jmp short taskforc.005948bd
 *  005948fd  |> 33c0           xor eax,eax
 *  005948ff  |> 5f             pop edi
 *  00594900  |. 5e             pop esi
 *  00594901  |. 5b             pop ebx
 *  00594902  \. c3             retn
 *
 *  Use this if that hook fails, try this one for future engines:
 *  /HS0@44CADA
 */
bool InsertTaskforce2Hook()
{
  const BYTE bytes[] = {
    0x88,0x02,  // 005948de  |. 8802           |mov byte ptr ds:[edx],al
    0x42,       // 005948e0  |. 42             |inc edx
    0x46,       // 005948e1  |. 46             |inc esi
    0x3a,0xc3,  // 005948e2  |. 3ac3           |cmp al,bl
    0x74, 0x03, // 005948e4  |. 74 03          |je short taskforc.005948e9
    0x4f,       // 005948e6  |. 4f             |dec edi
    0x75, 0xf3, // 005948e7  |.^75 f3          \jnz short taskforc.005948dc
    0x3b,0xfb   // 005948e9  |> 3bfb           cmp edi,ebx ; jichi: hook here
  };
  enum { hook_offset = sizeof(bytes) - 2 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD3(reladdr, module_base_, range);
  if (!addr) {
    ConsoleOutput("vnreng:Taskforce2: pattern not exist");
    //return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = -0xc;
  hp.type = BIG_ENDIAN|USING_STRING; // 0x41

  //ITH_GROWL_DWORD(hp.addr);
  //hp.addr = 0x1948e9 + module_base_;

  ConsoleOutput("vnreng: INSERT Taskforce2");
  NewHook(hp, L"Taskforce2");
  return true;
}

namespace { // unnamed Rejet
/**
 *  jichi 12/22/2013: Rejet
 *  See (CaoNiMaGeBi): http://www.hongfire.com/forum/printthread.php?t=36807&pp=40&page=172
 *  See (CaoNiMaGeBi): http://tieba.baidu.com/p/2506179113
 *  Pattern: 2bce8bf8
 *      2bce      sub ecx,esi ; hook here
 *      8bf8      mov eds,eax
 *      8bd1      mov edx,ecx
 *
 *  Examples:
 *  - Type1: ドットカレシ-We're 8bit Lovers!: /HBN-4*0@A5332:DotKareshi.exe
 *    length_offset: 1
 *    off: 0xfffffff8 (-0x8)
 *    type: 1096 (0x448)
 *
 *    module_base_ = 10e0000 (variant)
 *    hook_addr = module_base_ + reladdr = 0xe55332
 *    01185311   . FFF0           PUSH EAX  ; beginning of a new function
 *    01185313   . 0FC111         XADD DWORD PTR DS:[ECX],EDX
 *    01185316   . 4A             DEC EDX
 *    01185317   . 85D2           TEST EDX,EDX
 *    01185319   . 0F8F 45020000  JG DotKares.01185564
 *    0118531F   . 8B08           MOV ECX,DWORD PTR DS:[EAX]
 *    01185321   . 8B11           MOV EDX,DWORD PTR DS:[ECX]
 *    01185323   . 50             PUSH EAX
 *    01185324   . 8B42 04        MOV EAX,DWORD PTR DS:[EDX+0x4]
 *    01185327   . FFD0           CALL EAX
 *    01185329   . E9 36020000    JMP DotKares.01185564
 *    0118532E   . 8B7424 20      MOV ESI,DWORD PTR SS:[ESP+0x20]
 *    01185332   . E8 99A9FBFF    CALL DotKares.0113FCD0    ; hook here
 *    01185337   . 8BF0           MOV ESI,EAX
 *    01185339   . 8D4C24 14      LEA ECX,DWORD PTR SS:[ESP+0x14]
 *    0118533D   . 3BF7           CMP ESI,EDI
 *    0118533F   . 0F84 1A020000  JE DotKares.0118555F
 *    01185345   . 51             PUSH ECX                                 ; /Arg2
 *    01185346   . 68 E4FE5501    PUSH DotKares.0155FEE4                   ; |Arg1 = 0155FEE4
 *    0118534B   . E8 1023F9FF    CALL DotKares.01117660                   ; \DotKares.00377660
 *    01185350   . 83C4 08        ADD ESP,0x8
 *    01185353   . 84C0           TEST AL,AL
 *
 *  - Type2: ドットカレシ-We're 8bit Lovers! II: /HBN-8*0@A7AF9:dotkareshi.exe
 *    off: 4294967284 (0xfffffff4 = -0xc)
 *    length_offset: 1
 *    type: 1096 (0x448)
 *
 *    module_base_: 0x12b0000
 *
 *    01357ad2   . fff0           push eax ; beginning of a new function
 *    01357ad4   . 0fc111         xadd dword ptr ds:[ecx],edx
 *    01357ad7   . 4a             dec edx
 *    01357ad8   . 85d2           test edx,edx
 *    01357ada   . 7f 0a          jg short dotkares.01357ae6
 *    01357adc   . 8b08           mov ecx,dword ptr ds:[eax]
 *    01357ade   . 8b11           mov edx,dword ptr ds:[ecx]
 *    01357ae0   . 50             push eax
 *    01357ae1   . 8b42 04        mov eax,dword ptr ds:[edx+0x4]
 *    01357ae4   . ffd0           call eax
 *    01357ae6   > 8b4c24 14      mov ecx,dword ptr ss:[esp+0x14]
 *    01357aea   . 33ff           xor edi,edi
 *    01357aec   . 3979 f4        cmp dword ptr ds:[ecx-0xc],edi
 *    01357aef   . 0f84 1e020000  je dotkares.01357d13
 *    01357af5   . 8b7424 20      mov esi,dword ptr ss:[esp+0x20]
 *    01357af9   . e8 7283fbff    call dotkares.0130fe70    ; jichi: hook here
 *    01357afe   . 8bf0           mov esi,eax
 *    01357b00   . 3bf7           cmp esi,edi
 *    01357b02   . 0f84 0b020000  je dotkares.01357d13
 *    01357b08   . 8d5424 14      lea edx,dword ptr ss:[esp+0x14]
 *    01357b0c   . 52             push edx                                 ; /arg2
 *    01357b0d   . 68 cc9f7501    push dotkares.01759fcc                   ; |arg1 = 01759fcc
 *    01357b12   . e8 e9f9f8ff    call dotkares.012e7500                   ; \dotkares.012c7500
 *    01357b17   . 83c4 08        add esp,0x8
 *    01357b1a   . 84c0           test al,al
 *    01357b1c   . 74 1d          je short dotkares.01357b3b
 *    01357b1e   . 8d46 64        lea eax,dword ptr ds:[esi+0x64]
 *    01357b21   . e8 bad0f8ff    call dotkares.012e4be0
 *    01357b26   . 68 28a17501    push dotkares.0175a128                   ; /arg1 = 0175a128 ascii "<br>"
 *
 *  - Type2: Tiny×MACHINEGUN: /HBN-8*0@4CEB8:TinyMachinegun.exe
 *    module_base_: 0x12f0000
 *    There are two possible places to hook
 *
 *    0133cea0   . fff0           push eax ; beginning of a new function
 *    0133cea2   . 0fc111         xadd dword ptr ds:[ecx],edx
 *    0133cea5   . 4a             dec edx
 *    0133cea6   . 85d2           test edx,edx
 *    0133cea8   . 7f 0a          jg short tinymach.0133ceb4
 *    0133ceaa   . 8b08           mov ecx,dword ptr ds:[eax]
 *    0133ceac   . 8b11           mov edx,dword ptr ds:[ecx]
 *    0133ceae   . 50             push eax
 *    0133ceaf   . 8b42 04        mov eax,dword ptr ds:[edx+0x4]
 *    0133ceb2   . ffd0           call eax
 *    0133ceb4   > 8b4c24 14      mov ecx,dword ptr ss:[esp+0x14]
 *    0133ceb8   . 33db           xor ebx,ebx               ; jichi: hook here
 *    0133ceba   . 3959 f4        cmp dword ptr ds:[ecx-0xc],ebx
 *    0133cebd   . 0f84 d4010000  je tinymach.0133d097
 *    0133cec3   . 8b7424 20      mov esi,dword ptr ss:[esp+0x20]
 *    0133cec7   . e8 f4f90100    call tinymach.0135c8c0     ; jichi: or hook here
 *    0133cecc   . 8bf0           mov esi,eax
 *    0133cece   . 3bf3           cmp esi,ebx
 *    0133ced0   . 0f84 c1010000  je tinymach.0133d097
 *    0133ced6   . 8d5424 14      lea edx,dword ptr ss:[esp+0x14]
 *    0133ceda   . 52             push edx                                 ; /arg2
 *    0133cedb   . 68 44847d01    push tinymach.017d8444                   ; |arg1 = 017d8444
 *    0133cee0   . e8 eb5bfdff    call tinymach.01312ad0                   ; \tinymach.011b2ad0
 *
 *  - Type 3: 剣が君: /HBN-8*0@B357D:KenGaKimi.exe
 *
 *    01113550   . fff0           push eax
 *    01113552   . 0fc111         xadd dword ptr ds:[ecx],edx
 *    01113555   . 4a             dec edx
 *    01113556   . 85d2           test edx,edx
 *    01113558   . 7f 0a          jg short kengakim.01113564
 *    0111355a   . 8b08           mov ecx,dword ptr ds:[eax]
 *    0111355c   . 8b11           mov edx,dword ptr ds:[ecx]
 *    0111355e   . 50             push eax
 *    0111355f   . 8b42 04        mov eax,dword ptr ds:[edx+0x4]
 *    01113562   . ffd0           call eax
 *    01113564     8b4c24 14      mov ecx,dword ptr ss:[esp+0x14]
 *    01113568     33ff           xor edi,edi
 *    0111356a     3979 f4        cmp dword ptr ds:[ecx-0xc],edi
 *    0111356d     0f84 09020000  je kengakim.0111377c
 *    01113573     8d5424 14      lea edx,dword ptr ss:[esp+0x14]
 *    01113577     52             push edx
 *    01113578     68 dc6a5401    push kengakim.01546adc
 *    0111357d     e8 3eaff6ff    call kengakim.0107e4c0    ; hook here
 */
bool FindRejetHook(LPCVOID pattern, DWORD pattern_size, DWORD hook_off, DWORD hp_off, LPCWSTR hp_name = L"Rejet")
{
  // Offset to the function call from the beginning of the function
  //enum { hook_offset = 0x21 }; // Type1: hex(0x01185332-0x01185311)
  //const BYTE pattern[] = {    // Type1: Function start
  //  0xff,0xf0,      // 01185311   . fff0           push eax  ; beginning of a new function
  //  0x0f,0xc1,0x11, // 01185313   . 0fc111         xadd dword ptr ds:[ecx],edx
  //  0x4a,           // 01185316   . 4a             dec edx
  //  0x85,0xd2,      // 01185317   . 85d2           test edx,edx
  //  0x0f,0x8f       // 01185319   . 0f8f 45020000  jg DotKares.01185564
  //};
  //ITH_GROWL_DWORD(module_base_);
  ULONG addr = module_base_; //- sizeof(pattern);
  do {
    //addr += sizeof(pattern); // ++ so that each time return diff address
    ULONG range = min(module_limit_ - addr, MAX_REL_ADDR);
    addr = MemDbg::findBytes(pattern, pattern_size, addr, addr + range);
    if (!addr) {
      //ITH_MSG(L"failed");
      ConsoleOutput("vnreng:Rejet: pattern not found");
      return false;
    }

    addr += hook_off;
    //ITH_GROWL_DWORD(addr);
    //ITH_GROWL_DWORD(*(DWORD *)(addr-3));
    //const BYTE hook_ins[] = {
    //  /*0x8b,*/0x74,0x24, 0x20,  //    mov esi,dword ptr ss:[esp+0x20]
    //  0xe8 //??,??,??,??, 01357af9  e8 7283fbff call DotKares.0130fe70 ; jichi: hook here
    //};
  } while(0xe8202474 != *(DWORD *)(addr - 3));

  ConsoleOutput("vnreng: INSERT Rejet");
  HookParam hp = {};
  hp.addr = addr; //- 0xf;
  hp.type = NO_CONTEXT|DATA_INDIRECT|FIXING_SPLIT;
  hp.length_offset = 1;
  hp.off = hp_off;
  //hp.off = -0x8; // Type1
  //hp.off = -0xc; // Type2

  NewHook(hp, hp_name);
  return true;
}
bool InsertRejetHook1() // This type of hook has varied hook address
{
  const BYTE bytes[] = {  // Type1: Function start
    0xff,0xf0,          // 01185311   . fff0           push eax  ; beginning of a new function
    0x0f,0xc1,0x11,     // 01185313   . 0fc111         xadd dword ptr ds:[ecx],edx
    0x4a,               // 01185316   . 4a             dec edx
    0x85,0xd2,          // 01185317   . 85d2           test edx,edx
    0x0f,0x8f           // 01185319   . 0f8f 45020000  jg DotKares.01185564
  };
  // Offset to the function call from the beginning of the function
  enum { hook_offset = 0x21 }; // Type1: hex(0x01185332-0x01185311)
  enum { hp_off = -0x8 }; // hook parameter
  return FindRejetHook(bytes, sizeof(bytes), hook_offset, hp_off);
}
bool InsertRejetHook2() // This type of hook has static hook address
{
  const BYTE bytes[] = {   // Type2 Function start
    0xff,0xf0,           //   01357ad2   fff0           push eax
    0x0f,0xc1,0x11,      //   01357ad4   0fc111         xadd dword ptr ds:[ecx],edx
    0x4a,                //   01357ad7   4a             dec edx
    0x85,0xd2,           //   01357ad8   85d2           test edx,edx
    0x7f, 0x0a,          //   01357ada   7f 0a          jg short DotKares.01357ae6
    0x8b,0x08,           //   01357adc   8b08           mov ecx,dword ptr ds:[eax]
    0x8b,0x11,           //   01357ade   8b11           mov edx,dword ptr ds:[ecx]
    0x50,                //   01357ae0   50             push eax
    0x8b,0x42, 0x04,     //   01357ae1   8b42 04        mov eax,dword ptr ds:[edx+0x4]
    0xff,0xd0,           //   01357ae4   ffd0           call eax
    0x8b,0x4c,0x24, 0x14 //   01357ae6   8b4c24 14      mov ecx,dword ptr ss:[esp+0x14]
  };
  // Offset to the function call from the beginning of the function
  enum { hook_offset = 0x27 }; // Type2: hex(0x0133CEC7-0x0133CEA0) = hex(0x01357af9-0x1357ad2)
  enum { hp_off = -0xc }; // hook parameter
  return FindRejetHook(bytes, sizeof(bytes), hook_offset, hp_off);
}
bool InsertRejetHook3() // jichi 12/28/2013: add for 剣が君
{
  // The following pattern is the same as type2
  const BYTE bytes[] = {   // Type2 Function start
    0xff,0xf0,           //   01357ad2   fff0           push eax
    0x0f,0xc1,0x11,      //   01357ad4   0fc111         xadd dword ptr ds:[ecx],edx
    0x4a,                //   01357ad7   4a             dec edx
    0x85,0xd2,           //   01357ad8   85d2           test edx,edx
    0x7f, 0x0a,          //   01357ada   7f 0a          jg short DotKares.01357ae6
    0x8b,0x08,           //   01357adc   8b08           mov ecx,dword ptr ds:[eax]
    0x8b,0x11,           //   01357ade   8b11           mov edx,dword ptr ds:[ecx]
    0x50,                //   01357ae0   50             push eax
    0x8b,0x42, 0x04,     //   01357ae1   8b42 04        mov eax,dword ptr ds:[edx+0x4]
    0xff,0xd0,           //   01357ae4   ffd0           call eax
    0x8b,0x4c,0x24, 0x14 //   01357ae6   8b4c24 14      mov ecx,dword ptr ss:[esp+0x14]
  };
  // Offset to the function call from the beginning of the function
  //enum { hook_offset = 0x27 }; // Type2: hex(0x0133CEC7-0x0133CEA0) = hex(0x01357af9-0x1357ad2)
  enum { hp_off = -0xc }; // hook parameter
  ULONG addr = module_base_; //- sizeof(bytes);
  while (true) {
    //addr += sizeof(bytes); // ++ so that each time return diff address
    ULONG range = min(module_limit_ - addr, MAX_REL_ADDR);
    addr = MemDbg::findBytes(bytes, sizeof(bytes), addr, addr + range);
    if (!addr) {
      //ITH_MSG(L"failed");
      ConsoleOutput("vnreng:Rejet: pattern not found");
      return false;
    }
    addr += sizeof(bytes);
    // Push and call at once, i.e. push (0x68) and call (0xe8)
    // 01185345     52             push edx
    // 01185346   . 68 e4fe5501    push dotkares.0155fee4                   ; |arg1 = 0155fee4
    // 0118534b   . e8 1023f9ff    call dotkares.01117660                   ; \dotkares.00377660
    enum { start = 0x10, stop = 0x50 };
    // Different from FindRejetHook
    DWORD i;
    for (i = start; i < stop; i++)
      if (*(WORD *)(addr + i - 1) == 0x6852 && *(BYTE *)(addr + i + 5) == 0xe8) // 0118534B-01185346
        break;
    if (i < stop) {
      addr += i;
      break;
    }
  } //while(0xe8202474 != *(DWORD *)(addr - 3));

  //ITH_GROWL_DWORD(addr - module_base_); // = 0xb3578 for 剣が君

  ConsoleOutput("vnreng: INSERT Rejet");
  // The same as type2
  HookParam hp = {};
  hp.addr = addr; //- 0xf;
  hp.type = NO_CONTEXT|DATA_INDIRECT|FIXING_SPLIT;
  hp.length_offset = 1;
  hp.off = hp_off;
  //hp.off = -0x8; // Type1
  //hp.off = -0xc; // Type2

  NewHook(hp, L"Rejet");
  return true;
}
} // unnamed Rejet

bool InsertRejetHook()
{ return InsertRejetHook2() || InsertRejetHook1() || InsertRejetHook3(); } // insert hook2 first, since 2's pattern seems to be more unique

/**
 *  jichi 4/1/2014: Insert AU hook
 *  Sample games:
 *  英雄＊戦姫: /HBN-8*4@4AD807
 *  英雄＊戦姫GOLD: /HB-8*4@4ADB50 (alternative)
 *
 *  /HBN-8*4@4AD807
 *  - addr: 4904967 = 0x4ad807
 *  - ind: 4
 *  - length_offset: 1
 *  - off: 4294967284 = 0xfffffff4 = -0xc
 *  - type: 1032 = 0x408
 *
 *  004ad76a  |. ff50 04        |call dword ptr ds:[eax+0x4]
 *  004ad76d  |. 48             |dec eax                                 ;  switch (cases 1..a)
 *  004ad76e  |. 83f8 09        |cmp eax,0x9
 *  004ad771  |. 0f87 37020000  |ja 英雄＊戦.004ad9ae
 *  004ad777  |. ff2485 2cda4a0>|jmp dword ptr ds:[eax*4+0x4ada2c]
 *  004ad77e  |> 83bf c4000000 >|cmp dword ptr ds:[edi+0xc4],0x1         ;  case 1 of switch 004ad76d
 *  004ad785  |. 75 35          |jnz short 英雄＊戦.004ad7bc
 *  004ad787  |. 39af c8000000  |cmp dword ptr ds:[edi+0xc8],ebp
 *  004ad78d  |. 72 08          |jb short 英雄＊戦.004ad797
 *  004ad78f  |. 8b87 b4000000  |mov eax,dword ptr ds:[edi+0xb4]
 *  004ad795  |. eb 06          |jmp short 英雄＊戦.004ad79d
 *  004ad797  |> 8d87 b4000000  |lea eax,dword ptr ds:[edi+0xb4]
 *  004ad79d  |> 0fb608         |movzx ecx,byte ptr ds:[eax]
 *  004ad7a0  |. 51             |push ecx
 *  004ad7a1  |. e8 d15b2a00    |call 英雄＊戦.00753377
 *  004ad7a6  |. 83c4 04        |add esp,0x4
 *  004ad7a9  |. 85c0           |test eax,eax
 *  004ad7ab  |. 74 0f          |je short 英雄＊戦.004ad7bc
 *  004ad7ad  |. 8d5424 20      |lea edx,dword ptr ss:[esp+0x20]
 *  004ad7b1  |. 52             |push edx
 *  004ad7b2  |. b9 88567a00    |mov ecx,英雄＊戦.007a5688
 *  004ad7b7  |. e8 a40cf6ff    |call 英雄＊戦.0040e460
 *  004ad7bc  |> 8b8424 e400000>|mov eax,dword ptr ss:[esp+0xe4]
 *  004ad7c3  |. 8a48 01        |mov cl,byte ptr ds:[eax+0x1]
 *  004ad7c6  |. 84c9           |test cl,cl
 *  004ad7c8  |. 75 2e          |jnz short 英雄＊戦.004ad7f8
 *  004ad7ca  |. 8d9f b0000000  |lea ebx,dword ptr ds:[edi+0xb0]
 *  004ad7d0  |. be ac6e7a00    |mov esi,英雄＊戦.007a6eac
 *  004ad7d5  |. 8bcb           |mov ecx,ebx
 *  004ad7d7  |. e8 e40af6ff    |call 英雄＊戦.0040e2c0
 *  004ad7dc  |. 84c0           |test al,al
 *  004ad7de  |. 0f84 ca010000  |je 英雄＊戦.004ad9ae
 *  004ad7e4  |. be a86e7a00    |mov esi,英雄＊戦.007a6ea8
 *  004ad7e9  |. 8bcb           |mov ecx,ebx
 *  004ad7eb  |. e8 d00af6ff    |call 英雄＊戦.0040e2c0
 *  004ad7f0  |. 84c0           |test al,al
 *  004ad7f2  |. 0f84 b6010000  |je 英雄＊戦.004ad9ae
 *  004ad7f8  |> 6a 00          |push 0x0
 *  004ad7fa  |. 8d8f b0000000  |lea ecx,dword ptr ds:[edi+0xb0]
 *  004ad800  |. 83c8 ff        |or eax,0xffffffff
 *  004ad803  |. 8d5c24 24      |lea ebx,dword ptr ss:[esp+0x24]
 *  004ad807  |. e8 740cf6ff    |call 英雄＊戦.0040e480     ; jichi: hook here
 *  004ad80c  |. e9 9d010000    |jmp 英雄＊戦.004ad9ae
 *  004ad811  |> 8b8c24 e400000>|mov ecx,dword ptr ss:[esp+0xe4]         ;  case 4 of switch 004ad76d
 *  004ad818  |. 8039 00        |cmp byte ptr ds:[ecx],0x0
 *  004ad81b  |. 0f84 8d010000  |je 英雄＊戦.004ad9ae
 *  004ad821  |. b8 04000000    |mov eax,0x4
 *  004ad826  |. b9 c86e7a00    |mov ecx,英雄＊戦.007a6ec8                   ;  ascii "<br>"
 *  004ad82b  |. 8d5424 20      |lea edx,dword ptr ss:[esp+0x20]
 *  004ad82f  |. e8 3c0df6ff    |call 英雄＊戦.0040e570
 *  004ad834  |. e9 75010000    |jmp 英雄＊戦.004ad9ae
 *  004ad839  |> 8bbf b4000000  |mov edi,dword ptr ds:[edi+0xb4]         ;  case 5 of switch 004ad76d
 */
bool InsertTencoHook()
{
  const BYTE bytes[] = {
    0x6a, 0x00,                     // 004ad7f8  |> 6a 00          |push 0x0
    0x8d,0x8f, 0xb0,0x00,0x00,0x00, // 004ad7fa  |. 8d8f b0000000  |lea ecx,dword ptr ds:[edi+0xb0]
    0x83,0xc8, 0xff,                // 004ad800  |. 83c8 ff        |or eax,0xffffffff
    0x8d,0x5c,0x24, 0x24,           // 004ad803  |. 8d5c24 24      |lea ebx,dword ptr ss:[esp+0x24]
    0xe8 //740cf6ff                 // 004ad807  |. e8 740cf6ff    |call 英雄＊戦.0040e480     ; jichi: hook here
  };
  enum { hook_offset = sizeof(bytes) - 1 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //reladdr = 0x4ad807;
  if (!addr) {
    ConsoleOutput("vnreng:Tenco: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.length_offset = 1;
  hp.ind = 4;
  hp.off = -0xc;
  hp.type = NO_CONTEXT|DATA_INDIRECT;

  ConsoleOutput("vnreng: INSERT Tenco");
  NewHook(hp, L"Tenco");
  return true;
}

/**
 *  jichi 4/1/2014: Insert AOS hook
 *  About 彩文館: http://erogetrailers.com/brand/165
 *  About AOS: http://asmodean.reverse.net/pages/exaos.html
 *
 *  Sample games:
 *
 *  [140228] [Sugar Pot] 恋する少女と想いのキセキ V1.00 H-CODE by 소쿠릿
 *  - /HB8*0@3C2F0:恋する少女と想いのキセキ.exe
 *  - /HBC*0@3C190:恋する少女と想いのキセキ.exe
 *
 *  [120224] [Sugar Pot]  ツクモノツキ
 *
 *  LiLiM games
 *
 *  /HB8*0@3C2F0:恋する少女と想いのキセ
 *  - addr: 246512 = 0x3c2f0
 *  - length_offset: 1
 *  - module: 1814017450
 *  - off: 8
 *  - type: 72 = 0x48
 *
 *  00e3c2ed     cc                         int3
 *  00e3c2ee     cc                         int3
 *  00e3c2ef     cc                         int3
 *  00e3c2f0  /$ 51                         push ecx    ; jichi: hook here, function starts
 *  00e3c2f1  |. a1 0c64eb00                mov eax,dword ptr ds:[0xeb640c]
 *  00e3c2f6  |. 8b0d 7846eb00              mov ecx,dword ptr ds:[0xeb4678]
 *  00e3c2fc  |. 53                         push ebx
 *  00e3c2fd  |. 55                         push ebp
 *  00e3c2fe  |. 8b6c24 10                  mov ebp,dword ptr ss:[esp+0x10]
 *  00e3c302  |. 56                         push esi
 *  00e3c303  |. 8b35 c446eb00              mov esi,dword ptr ds:[0xeb46c4]
 *  00e3c309  |. 57                         push edi
 *  00e3c30a  |. 0fb63d c746eb00            movzx edi,byte ptr ds:[0xeb46c7]
 *  00e3c311  |. 81e6 ffffff00              and esi,0xffffff
 *  00e3c317  |. 894424 18                  mov dword ptr ss:[esp+0x18],eax
 *  00e3c31b  |. 85ff                       test edi,edi
 *  00e3c31d  |. 74 6b                      je short 恋する少.00e3c38a
 *  00e3c31f  |. 8bd9                       mov ebx,ecx
 *  00e3c321  |. 85db                       test ebx,ebx
 *  00e3c323  |. 74 17                      je short 恋する少.00e3c33c
 *  00e3c325  |. 8b4b 28                    mov ecx,dword ptr ds:[ebx+0x28]
 *  00e3c328  |. 56                         push esi                                 ; /color
 *  00e3c329  |. 51                         push ecx                                 ; |hdc
 *  00e3c32a  |. ff15 3c40e800              call dword ptr ds:[<&gdi32.SetTextColor>>; \settextcolor
 *  00e3c330  |. 89b3 c8000000              mov dword ptr ds:[ebx+0xc8],esi
 *  00e3c336  |. 8b0d 7846eb00              mov ecx,dword ptr ds:[0xeb4678]
 *  00e3c33c  |> 0fbf55 1c                  movsx edx,word ptr ss:[ebp+0x1c]
 *  00e3c340  |. 0fbf45 0a                  movsx eax,word ptr ss:[ebp+0xa]
 *  00e3c344  |. 0fbf75 1a                  movsx esi,word ptr ss:[ebp+0x1a]
 *  00e3c348  |. 03d7                       add edx,edi
 *  00e3c34a  |. 03c2                       add eax,edx
 *  00e3c34c  |. 0fbf55 08                  movsx edx,word ptr ss:[ebp+0x8]
 *  00e3c350  |. 03f7                       add esi,edi
 *  00e3c352  |. 03d6                       add edx,esi
 *  00e3c354  |. 85c9                       test ecx,ecx
 *  00e3c356  |. 74 32                      je short 恋する少.00e3c38a
 */
bool InsertAOSHook()
{
  // jichi 4/2/2014: The starting of this function is different from ツクモノツキ
  // So, use a pattern in the middle of the function instead.
  //
  //const BYTE bytes[] = {
  //  0x51,                                 // 00e3c2f0  /$ 51              push ecx    ; jichi: hook here, function begins
  //  0xa1, 0x0c,0x64,0xeb,0x00,            // 00e3c2f1  |. a1 0c64eb00     mov eax,dword ptr ds:[0xeb640c]
  //  0x8b,0x0d, 0x78,0x46,0xeb,0x00,       // 00e3c2f6  |. 8b0d 7846eb00   mov ecx,dword ptr ds:[0xeb4678]
  //  0x53,                                 // 00e3c2fc  |. 53              push ebx
  //  0x55,                                 // 00e3c2fd  |. 55              push ebp
  //  0x8b,0x6c,0x24, 0x10,                 // 00e3c2fe  |. 8b6c24 10       mov ebp,dword ptr ss:[esp+0x10]
  //  0x56,                                 // 00e3c302  |. 56              push esi
  //  0x8b,0x35, 0xc4,0x46,0xeb,0x00,       // 00e3c303  |. 8b35 c446eb00   mov esi,dword ptr ds:[0xeb46c4]
  //  0x57,                                 // 00e3c309  |. 57              push edi
  //  0x0f,0xb6,0x3d, 0xc7,0x46,0xeb,0x00,  // 00e3c30a  |. 0fb63d c746eb00 movzx edi,byte ptr ds:[0xeb46c7]
  //  0x81,0xe6, 0xff,0xff,0xff,0x00        // 00e3c311  |. 81e6 ffffff00   and esi,0xffffff
  //};
  //enum { hook_offset = 0 };

  const BYTE bytes[] = {
    0x0f,0xbf,0x55, 0x1c,   // 00e3c33c  |> 0fbf55 1c                  movsx edx,word ptr ss:[ebp+0x1c]
    0x0f,0xbf,0x45, 0x0a,   // 00e3c340  |. 0fbf45 0a                  movsx eax,word ptr ss:[ebp+0xa]
    0x0f,0xbf,0x75, 0x1a,   // 00e3c344  |. 0fbf75 1a                  movsx esi,word ptr ss:[ebp+0x1a]
    0x03,0xd7,              // 00e3c348  |. 03d7                       add edx,edi
    0x03,0xc2,              // 00e3c34a  |. 03c2                       add eax,edx
    0x0f,0xbf,0x55, 0x08,   // 00e3c34c  |. 0fbf55 08                  movsx edx,word ptr ss:[ebp+0x8]
    0x03,0xf7,              // 00e3c350  |. 03f7                       add esi,edi
    0x03,0xd6,              // 00e3c352  |. 03d6                       add edx,esi
    0x85,0xc9               // 00e3c354  |. 85c9                       test ecx,ecx
  };
  enum { hook_offset = 0x00e3c2f0 - 0x00e3c33c }; // distance to the beginning of the function, which is 0x51 (push ecx)
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL(reladdr);
  if (!addr) {
    ConsoleOutput("vnreng:AOS: pattern not found");
    return false;
  }
  addr += hook_offset;
  //ITH_GROWL(addr);
  enum { push_ecx = 0x51 }; // beginning of the function
  if (*(BYTE *)addr != push_ecx) {
    ConsoleOutput("vnreng:AOS: beginning of the function not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.length_offset = 1;
  hp.off = 8;
  hp.type = DATA_INDIRECT;

  ConsoleOutput("vnreng: INSERT AOS");
  NewHook(hp, L"AOS");
  return true;
}

/**
 *  jichi 4/15/2014: Insert Adobe AIR hook
 *  Sample games:
 *  華アワセ 蛟編: /HW-C*0:D8@4D04B5:Adobe AIR.dll
 *  華アワセ 姫空木編: /HW-C*0:d8@4E69A7:Adobe AIR.dll
 *
 *  Issue: The game will hang if the hook is injected before loading
 *
 *  /HW-C*0:D8@4D04B5:ADOBE AIR.DLL
 *  - addr: 5047477 = 0x4d04b5
 *  -length_offset: 1
 *  - module: 3506957663 = 0xd107ed5f
 *  - off: 4294967280 = 0xfffffff0 = -0x10
 *  - split: 216 = 0xd8
 *  - type: 90 = 0x5a
 *
 *  0f8f0497  |. eb 69         jmp short adobe_ai.0f8f0502
 *  0f8f0499  |> 83c8 ff       or eax,0xffffffff
 *  0f8f049c  |. eb 67         jmp short adobe_ai.0f8f0505
 *  0f8f049e  |> 8b7d 0c       mov edi,dword ptr ss:[ebp+0xc]
 *  0f8f04a1  |. 85ff          test edi,edi
 *  0f8f04a3  |. 7e 5d         jle short adobe_ai.0f8f0502
 *  0f8f04a5  |. 8b55 08       mov edx,dword ptr ss:[ebp+0x8]
 *  0f8f04a8  |. b8 80000000   mov eax,0x80
 *  0f8f04ad  |. be ff030000   mov esi,0x3ff
 *  0f8f04b2  |> 0fb70a        /movzx ecx,word ptr ds:[edx]
 *  0f8f04b5  |. 8bd8          |mov ebx,eax ; jichi: hook here
 *  0f8f04b7  |. 4f            |dec edi
 *  0f8f04b8  |. 66:3bcb       |cmp cx,bx
 *  0f8f04bb  |. 73 05         |jnb short adobe_ai.0f8f04c2
 *  0f8f04bd  |. ff45 fc       |inc dword ptr ss:[ebp-0x4]
 *  0f8f04c0  |. eb 3a         |jmp short adobe_ai.0f8f04fc
 *  0f8f04c2  |> bb 00080000   |mov ebx,0x800
 *  0f8f04c7  |. 66:3bcb       |cmp cx,bx
 *  0f8f04ca  |. 73 06         |jnb short adobe_ai.0f8f04d2
 *  0f8f04cc  |. 8345 fc 02    |add dword ptr ss:[ebp-0x4],0x2
 *  0f8f04d0  |. eb 2a         |jmp short adobe_ai.0f8f04fc
 *  0f8f04d2  |> 81c1 00280000 |add ecx,0x2800
 *  0f8f04d8  |. 8bde          |mov ebx,esi
 *  0f8f04da  |. 66:3bcb       |cmp cx,bx
 *  0f8f04dd  |. 77 19         |ja short adobe_ai.0f8f04f8
 *  0f8f04df  |. 4f            |dec edi
 *  0f8f04e0  |.^78 b7         |js short adobe_ai.0f8f0499
 *  0f8f04e2  |. 42            |inc edx
 *  0f8f04e3  |. 42            |inc edx
 *  0f8f04e4  |. 0fb70a        |movzx ecx,word ptr ds:[edx]
 *  0f8f04e7  |. 81c1 00240000 |add ecx,0x2400
 *  0f8f04ed  |. 66:3bcb       |cmp cx,bx
 *  0f8f04f0  |. 77 06         |ja short adobe_ai.0f8f04f8
 *  0f8f04f2  |. 8345 fc 04    |add dword ptr ss:[ebp-0x4],0x4
 *  0f8f04f6  |. eb 04         |jmp short adobe_ai.0f8f04fc
 *  0f8f04f8  |> 8345 fc 03    |add dword ptr ss:[ebp-0x4],0x3
 *  0f8f04fc  |> 42            |inc edx
 *  0f8f04fd  |. 42            |inc edx
 *  0f8f04fe  |. 85ff          |test edi,edi
 *  0f8f0500  |.^7f b0         \jg short adobe_ai.0f8f04b2
 *  0f8f0502  |> 8b45 fc       mov eax,dword ptr ss:[ebp-0x4]
 *  0f8f0505  |> 5f            pop edi
 *  0f8f0506  |. 5e            pop esi
 *  0f8f0507  |. 5b            pop ebx
 *  0f8f0508  |. c9            leave
 *  0f8f0509  \. c3            retn
 */
bool InsertAdobeAirHook()
{
  enum { module = 0xd107ed5f }; // hash of "Adobe AIR.dll"
  DWORD base = Util::FindModuleBase(module);
  if (!base) {
    ConsoleOutput("vnreng:Adobe AIR: module not found");
    return false;
  }

  const BYTE bytes[] = {
    0x0f,0xb7,0x0a,  // 0f8f04b2  |> 0fb70a        /movzx ecx,word ptr ds:[edx]
    0x8b,0xd8,       // 0f8f04b5  |. 8bd8          |mov ebx,eax ; jichi: hook here
    0x4f,            // 0f8f04b7  |. 4f            |dec edi
    0x66,0x3b,0xcb,  // 0f8f04b8  |. 66:3bcb       |cmp cx,bx
    0x73, 0x05,      // 0f8f04bb  |. 73 05         |jnb short adobe_ai.0f8f04c2
    0xff,0x45, 0xfc, // 0f8f04bd  |. ff45 fc       |inc dword ptr ss:[ebp-0x4]
    0xeb, 0x3a       // 0f8f04c0  |. eb 3a         |jmp short adobe_ai.0f8f04fc
  };
  enum { hook_offset = 0x0f8f04b5 - 0x0f8f04b2 }; // = 3. 0 also works.
  enum { range = 0x600000 }; // larger than relative addresses
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), base, base + range);
  //ITH_GROWL(reladdr);
  if (!addr) {
    ConsoleOutput("vnreng:Adobe AIR: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  //hp.module = module;
  hp.length_offset = 1;
  hp.off = -0x10;
  hp.split = 0xd8;
  //hp.type = USING_SPLIT|MODULE_OFFSET|USING_UNICODE|DATA_INDIRECT; // 0x5a;
  hp.type = USING_SPLIT|USING_UNICODE|DATA_INDIRECT;

  ConsoleOutput("vnreng: INSERT Adobe AIR");
  NewHook(hp, L"Adobe AIR");
  return true;
}

/**
 *  jichi 1/10/2014: Rai7 puk
 *  See: http://www.hongfire.com/forum/showthread.php/421909-%E3%80%90Space-Warfare-Sim%E3%80%91Rai-7-PUK/page10
 *  See: www.hongfire.com/forum/showthread.php/421909-%E3%80%90Space-Warfare-Sim%E3%80%91Rai-7-PUK/page19
 *
 *  Version: R7P3-13v2(131220).rar, pass: sstm http://pan.baidu.com/share/home?uk=3727185265#category/type=0
 *  /HS0@409524
 */
//bool InsertRai7Hook()
//{
//}

/**
 *  jichi 10/1/2013: sol-fa-soft
 *  See (tryguy): http://www.hongfire.com/forum/printthread.php?t=36807&pp=10&page=639
 *
 *  @tryguy
 *  [sol-fa-soft]
 *  17 スク水不要論: /HA4@4AD140
 *  18 ななちゃんといっしょ: /HA4@5104A0
 *  19 発情てんこうせい: /HA4@51D720
 *  20 わたしのたまごさん: /HA4@4968E0
 *  21 修学旅行夜更かし組: /HA4@49DC00
 *  22 おぼえたてキッズ: /HA4@49DDB0
 *  23 ちっさい巫女さんSOS: /HA4@4B4AA0
 *  24 はじめてのおふろやさん: /HA4@4B5600
 *  25 はきわすれ愛好会: /HA4@57E360
 *  26 朝っぱらから発情家族: /HA4@57E360
 *  27 となりのヴァンパイア: /HA4@5593B0
 *  28 麦わら帽子と水辺の妖精: /HA4@5593B0
 *  29 海と温泉と夏休み: /HA4@6DE8E0
 *  30 駄菓子屋さん繁盛記: /HA4@6DEC90
 *  31 浴衣の下は… ～神社で発見！ ノーパン少女～: /HA4@6DEC90
 *  32 プールのじかん スク水不要論2: /HA4@62AE10
 *  33 妹のお泊まり会: /HA4@6087A0
 *  34 薄着少女: /HA4@6087A0
 *  35 あやめ Princess Intermezzo: /HA4@609BF0
 *
 *  SG01 男湯Ｒ: /HA4@6087A0
 *
 *  c71 真冬の大晦日CD: /HA4@516b50
 *  c78 sol-fa-soft真夏のお気楽CD: /HA4@6DEC90
 *
 *  Example: 35 あやめ Princess Intermezzo: /HA4@609BF0
 *  - addr: 6331376 = 0x609bf0
 *  - length_offset: 1
 *  - off: 4
 *  - type: 4
 *
 *  ASCII: あやめ, hook_offset = -50
 *  Function starts
 *  00609bef  /> cc             int3
 *  00609bf0  /> 55             push ebp
 *  00609bf1  |. 8bec           mov ebp,esp
 *  00609bf3  |. 64:a1 00000000 mov eax,dword ptr fs:[0]
 *  00609bf9  |. 6a ff          push -0x1
 *  00609bfb  |. 68 e1266300    push あやめ.006326e1
 *  00609c00  |. 50             push eax
 *  00609c01  |. 64:8925 000000>mov dword ptr fs:[0],esp
 *  00609c08  |. 81ec 80000000  sub esp,0x80
 *  00609c0e  |. 53             push ebx
 *  00609c0f  |. 8b5d 08        mov ebx,dword ptr ss:[ebp+0x8]
 *  00609c12  |. 57             push edi
 *  00609c13  |. 8bf9           mov edi,ecx
 *  00609c15  |. 8b07           mov eax,dword ptr ds:[edi]
 *  00609c17  |. 83f8 02        cmp eax,0x2
 *  00609c1a  |. 75 1f          jnz short あやめ.00609c3b
 *  00609c1c  |. 3b5f 40        cmp ebx,dword ptr ds:[edi+0x40]
 *  00609c1f  |. 75 1a          jnz short あやめ.00609c3b
 *  00609c21  |. 837f 44 00     cmp dword ptr ds:[edi+0x44],0x0
 *  00609c25  |. 74 14          je short あやめ.00609c3b
 *  00609c27  |. 5f             pop edi
 *  00609c28  |. b0 01          mov al,0x1
 *  00609c2a  |. 5b             pop ebx
 *  00609c2b  |. 8b4d f4        mov ecx,dword ptr ss:[ebp-0xc]
 *  00609c2e  |. 64:890d 000000>mov dword ptr fs:[0],ecx
 *  00609c35  |. 8be5           mov esp,ebp
 *  00609c37  |. 5d             pop ebp
 *  00609c38  |. c2 0400        retn 0x4
 *  Function stops
 *
 *  WideChar: こいなか-小田舎で初恋x中出しセクシャルライフ-, hook_offset = -53
 *  0040653a     cc             int3
 *  0040653b     cc             int3
 *  0040653c     cc             int3
 *  0040653d     cc             int3
 *  0040653e     cc             int3
 *  0040653f     cc             int3
 *  00406540   > 55             push ebp
 *  00406541   . 8bec           mov ebp,esp
 *  00406543   . 64:a1 00000000 mov eax,dword ptr fs:[0]
 *  00406549   . 6a ff          push -0x1
 *  0040654b   . 68 f1584300    push erondo01.004358f1
 *  00406550   . 50             push eax
 *  00406551   . 64:8925 000000>mov dword ptr fs:[0],esp
 *  00406558   . 83ec 6c        sub esp,0x6c
 *  0040655b   . 53             push ebx
 *  0040655c   . 8bd9           mov ebx,ecx
 *  0040655e   . 57             push edi
 *  0040655f   . 8b03           mov eax,dword ptr ds:[ebx]
 *  00406561   . 8b7d 08        mov edi,dword ptr ss:[ebp+0x8]
 *  00406564   . 83f8 02        cmp eax,0x2
 *  00406567   . 75 1f          jnz short erondo01.00406588
 *  00406569   . 3b7b 3c        cmp edi,dword ptr ds:[ebx+0x3c]
 *  0040656c   . 75 1a          jnz short erondo01.00406588
 *  0040656e   . 837b 40 00     cmp dword ptr ds:[ebx+0x40],0x0
 *  00406572   . 74 14          je short erondo01.00406588
 *  00406574   . 5f             pop edi
 *  00406575   . b0 01          mov al,0x1
 *  00406577   . 5b             pop ebx
 *  00406578   . 8b4d f4        mov ecx,dword ptr ss:[ebp-0xc]
 *  0040657b   . 64:890d 000000>mov dword ptr fs:[0],ecx
 *  00406582   . 8be5           mov esp,ebp
 *  00406584   . 5d             pop ebp
 *  00406585   . c2 0400        retn 0x4
 *
 *  WideChar: 祝福の鐘の音は、桜色の風と共に, hook_offset = -50,
 *  FIXME: how to know if it is UTF16? This game has /H code, though:
 *
 *      /HA-4@94D62:shukufuku_main.exe
 *
 *  011d619e   cc               int3
 *  011d619f   cc               int3
 *  011d61a0   55               push ebp
 *  011d61a1   8bec             mov ebp,esp
 *  011d61a3   64:a1 00000000   mov eax,dword ptr fs:[0]
 *  011d61a9   6a ff            push -0x1
 *  011d61ab   68 d1811f01      push .011f81d1
 *  011d61b0   50               push eax
 *  011d61b1   64:8925 00000000 mov dword ptr fs:[0],esp
 *  011d61b8   81ec 80000000    sub esp,0x80
 *  011d61be   53               push ebx
 *  011d61bf   8b5d 08          mov ebx,dword ptr ss:[ebp+0x8]
 *  011d61c2   57               push edi
 *  011d61c3   8bf9             mov edi,ecx
 *  011d61c5   8b07             mov eax,dword ptr ds:[edi]
 *  011d61c7   83f8 02          cmp eax,0x2
 *  011d61ca   75 1f            jnz short .011d61eb
 *  011d61cc   3b5f 40          cmp ebx,dword ptr ds:[edi+0x40]
 *  011d61cf   75 1a            jnz short .011d61eb
 *  011d61d1   837f 44 00       cmp dword ptr ds:[edi+0x44],0x0
 *  011d61d5   74 14            je short .011d61eb
 *  011d61d7   5f               pop edi
 *  011d61d8   b0 01            mov al,0x1
 *  011d61da   5b               pop ebx
 *  011d61db   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  011d61de   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  011d61e5   8be5             mov esp,ebp
 *  011d61e7   5d               pop ebp
 *  011d61e8   c2 0400          retn 0x4
 */
bool InsertScenarioPlayerHook()
{
  //const BYTE bytes[] = {
  //  0x53,                    // 00609c0e  |. 53             push ebx
  //  0x8b,0x5d,0x08,          // 00609c0f  |. 8b5d 08        mov ebx,dword ptr ss:[ebp+0x8]
  //  0x57,                    // 00609c12  |. 57             push edi
  //  0x8b,0xf9,               // 00609c13  |. 8bf9           mov edi,ecx
  //  0x8b,0x07,               // 00609c15  |. 8b07           mov eax,dword ptr ds:[edi]
  //  0x83,0xf8, 0x02,         // 00609c17  |. 83f8 02        cmp eax,0x2
  //  0x75, 0x1f,              // 00609c1a  |. 75 1f          jnz short あやめ.00609c3b
  //  0x3b,0x5f, 0x40,         // 00609c1c  |. 3b5f 40        cmp ebx,dword ptr ds:[edi+0x40]
  //  0x75, 0x1a,              // 00609c1f  |. 75 1a          jnz short あやめ.00609c3b
  //  0x83,0x7f, 0x44, 0x00,   // 00609c21  |. 837f 44 00     cmp dword ptr ds:[edi+0x44],0x0
  //  0x74, 0x14,              // 00609c25  |. 74 14          je short あやめ.00609c3b
  //};
  //enum { hook_offset = 0x00609bf0 - 0x00609c0e }; // distance to the beginning of the function

  const BYTE bytes[] = {
    0x74, 0x14,     // 00609c25  |. 74 14          je short あやめ.00609c3b
    0x5f,           // 00609c27  |. 5f             pop edi
    0xb0, 0x01,     // 00609c28  |. b0 01          mov al,0x1
    0x5b,           // 00609c2a  |. 5b             pop ebx
    0x8b,0x4d, 0xf4 // 00609c2b  |. 8b4d f4        mov ecx,dword ptr ss:[ebp-0xc]
  };
  enum { // distance to the beginning of the function
    hook_offset_A = 0x00609bf0 - 0x00609c25   // -53
    , hook_offset_W = 0x00406540 - 0x00406572 // -50
  };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG start = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  if (!start) {
    ConsoleOutput("vnreng:ScenarioPlayer: pattern not found");
    return false;
  }

  DWORD addr = MemDbg::findEnclosingAlignedFunction(start, 80); // range is around 50, use 80

  enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
  if (!addr || *(BYTE *)addr != push_ebp) {
    ConsoleOutput("vnreng:ScenarioPlayer: pattern found but the function offset is invalid");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.length_offset = 1;
  hp.off = 4;
  if (addr - start == hook_offset_W) {
    hp.type = USING_UNICODE;
    ConsoleOutput("vnreng: INSERT ScenarioPlayerW");
    NewHook(hp, L"ScenarioPlayerW");
  } else {
    hp.type = BIG_ENDIAN; // 4
    ConsoleOutput("vnreng: INSERT ScenarioPlayerA");
    NewHook(hp, L"ScenarioPlayerA");
  }
  return true;
}

/**
 *  jichi 4/19/2014: Marine Heart
 *  See: http://blgames.proboards.com/post/1984
 *       http://www.yaoiotaku.com/forums/threads/11440-huge-bl-game-torrent
 *
 *  Issue: The extracted text someitems has limited repetition
 *  TODO: It might be better to use FindCallAndEntryAbs for gdi32.CreateFontA?
 *        See how FindCallAndEntryAbs is used in Majiro.
 *
 *  妖恋愛奇譚 ～神サマの堕し方～ /HS4*0@40D160
 *  - addr: 4247904 = 0x40d160
 *  - off: 4
 *  - type: 9
 *
 *  Function starts
 *  0040d160  /$ 55                 push ebp    ; jichi: hook here
 *  0040d161  |. 8bec               mov ebp,esp
 *  0040d163  |. 83c4 90            add esp,-0x70
 *  0040d166  |. 33c0               xor eax,eax
 *  0040d168  |. 53                 push ebx
 *  0040d169  |. 56                 push esi
 *  0040d16a  |. 57                 push edi
 *  0040d16b  |. 8b75 08            mov esi,dword ptr ss:[ebp+0x8]
 *  0040d16e  |. c745 cc 281e4800   mov dword ptr ss:[ebp-0x34],saisys.00481>
 *  0040d175  |. 8965 d0            mov dword ptr ss:[ebp-0x30],esp
 *  0040d178  |. c745 c8 d0d14700   mov dword ptr ss:[ebp-0x38],<jmp.&cp3245>
 *  0040d17f  |. 66:c745 d4 0000    mov word ptr ss:[ebp-0x2c],0x0
 *  0040d185  |. 8945 e0            mov dword ptr ss:[ebp-0x20],eax
 *  0040d188  |. 64:8b15 00000000   mov edx,dword ptr fs:[0]
 *  0040d18f  |. 8955 c4            mov dword ptr ss:[ebp-0x3c],edx
 *  0040d192  |. 8d4d c4            lea ecx,dword ptr ss:[ebp-0x3c]
 *  0040d195  |. 64:890d 00000000   mov dword ptr fs:[0],ecx
 *  0040d19c  |. 8b05 741c4800      mov eax,dword ptr ds:[0x481c74]
 *  0040d1a2  |. 8945 bc            mov dword ptr ss:[ebp-0x44],eax
 *  0040d1a5  |. 8b05 781c4800      mov eax,dword ptr ds:[0x481c78]
 *  0040d1ab  |. 8945 c0            mov dword ptr ss:[ebp-0x40],eax
 *  0040d1ae  |. 8d46 24            lea eax,dword ptr ds:[esi+0x24]
 *  0040d1b1  |. 8b56 14            mov edx,dword ptr ds:[esi+0x14]
 *  0040d1b4  |. 8955 bc            mov dword ptr ss:[ebp-0x44],edx
 *  0040d1b7  |. 8b10               mov edx,dword ptr ds:[eax]
 *  0040d1b9  |. 85d2               test edx,edx
 *  0040d1bb  |. 74 04              je short saisys.0040d1c1
 *  0040d1bd  |. 8b08               mov ecx,dword ptr ds:[eax]
 *  0040d1bf  |. eb 05              jmp short saisys.0040d1c6
 *  0040d1c1  |> b9 9b1c4800        mov ecx,saisys.00481c9b
 *  0040d1c6  |> 51                 push ecx                                 ; /facename
 *  0040d1c7  |. 6a 01              push 0x1                                 ; |pitchandfamily = fixed_pitch|ff_dontcare
 *  0040d1c9  |. 6a 03              push 0x3                                 ; |quality = 3.
 *  0040d1cb  |. 6a 00              push 0x0                                 ; |clipprecision = clip_default_precis
 *  0040d1cd  |. 6a 00              push 0x0                                 ; |outputprecision = out_default_precis
 *  0040d1cf  |. 68 80000000        push 0x80                                ; |charset = 128.
 *  0040d1d4  |. 6a 00              push 0x0                                 ; |strikeout = false
 *  0040d1d6  |. 6a 00              push 0x0                                 ; |underline = false
 *  0040d1d8  |. 6a 00              push 0x0                                 ; |italic = false
 *  0040d1da  |. 68 90010000        push 0x190                               ; |weight = fw_normal
 *  0040d1df  |. 6a 00              push 0x0                                 ; |orientation = 0x0
 *  0040d1e1  |. 6a 00              push 0x0                                 ; |escapement = 0x0
 *  0040d1e3  |. 6a 00              push 0x0                                 ; |width = 0x0
 *  0040d1e5  |. 8b46 04            mov eax,dword ptr ds:[esi+0x4]           ; |
 *  0040d1e8  |. 50                 push eax                                 ; |height
 *  0040d1e9  |. e8 00fa0600        call <jmp.&gdi32.CreateFontA>            ; \createfonta
 *  0040d1ee  |. 8945 b8            mov dword ptr ss:[ebp-0x48],eax
 *  0040d1f1  |. 8b55 b8            mov edx,dword ptr ss:[ebp-0x48]
 *  0040d1f4  |. 85d2               test edx,edx
 *  0040d1f6  |. 75 14              jnz short saisys.0040d20c
 */
bool InsertMarineHeartHook()
{
  // FIXME: Why this does not work?!
  // jichi 6/3/2014: CreateFontA is only called once in this function
  //  0040d160  /$ 55                 push ebp    ; jichi: hook here
  //  0040d161  |. 8bec               mov ebp,esp
  //ULONG addr = Util::FindCallAndEntryAbs((DWORD)CreateFontA, module_limit_ - module_base_, module_base_, 0xec8b);

  const BYTE bytes[] = {
    0x51,                       // 0040d1c6  |> 51                 push ecx                        ; /facename
    0x6a, 0x01,                 // 0040d1c7  |. 6a 01              push 0x1                        ; |pitchandfamily = fixed_pitch|ff_dontcare
    0x6a, 0x03,                 // 0040d1c9  |. 6a 03              push 0x3                        ; |quality = 3.
    0x6a, 0x00,                 // 0040d1cb  |. 6a 00              push 0x0                        ; |clipprecision = clip_default_precis
    0x6a, 0x00,                 // 0040d1cd  |. 6a 00              push 0x0                        ; |outputprecision = out_default_precis
    0x68, 0x80,0x00,0x00,0x00,  // 0040d1cf  |. 68 80000000        push 0x80                       ; |charset = 128.
    0x6a, 0x00,                 // 0040d1d4  |. 6a 00              push 0x0                        ; |strikeout = false
    0x6a, 0x00,                 // 0040d1d6  |. 6a 00              push 0x0                        ; |underline = false
    0x6a, 0x00,                 // 0040d1d8  |. 6a 00              push 0x0                        ; |italic = false
    0x68, 0x90,0x01,0x00,0x00,  // 0040d1da  |. 68 90010000        push 0x190                      ; |weight = fw_normal
    0x6a, 0x00,                 // 0040d1df  |. 6a 00              push 0x0                        ; |orientation = 0x0
    0x6a, 0x00,                 // 0040d1e1  |. 6a 00              push 0x0                        ; |escapement = 0x0
    0x6a, 0x00,                 // 0040d1e3  |. 6a 00              push 0x0                        ; |width = 0x0 0x8b,0x46, 0x04,
    0x8b,0x46, 0x04,            // 0040d1e5  |. 8b46 04            mov eax,dword ptr ds:[esi+0x4]  ; |
    0x50,                       // 0040d1e8  |. 50                 push eax                        ; |height
    0xe8, 0x00,0xfa,0x06,0x00   // 0040d1e9  |. e8 00fa0600        call <jmp.&gdi32.CreateFontA>   ; \createfonta
  };
  enum { hook_offset = 0x0040d160 - 0x0040d1c6 }; // distance to the beginning of the function
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(reladdr);
  if (!addr) {
    ConsoleOutput("vnreng:MarineHeart: pattern not found");
    return false;
  }

  addr += hook_offset;
  //addr = 0x40d160;
  //ITH_GROWL_DWORD(addr);
  enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
  if (*(BYTE *)addr != push_ebp) {
    ConsoleOutput("vnreng:MarineHeart: pattern found but the function offset is invalid");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.off = 4;
  hp.type = USING_STRING|DATA_INDIRECT; // = 9

  ConsoleOutput("vnreng: INSERT MarineHeart");
  NewHook(hp, L"MarineHeart");
  return true;
}

/**
 *  jichi 6/1/2014:
 *  Observations from 愛姉妹4
 *  - Scenario: arg1 + 4*5 is 0, arg1+0xc is address of the text
 *  - Character: arg1 + 4*10 is 0, arg1+0xc is text
 */
static inline size_t _elf_strlen(LPCSTR p) // limit search address which might be bad
{
  //CC_ASSERT(p);
  for (size_t i = 0; i < VNR_TEXT_CAPACITY; i++)
    if (!*p++)
      return i;
  return 0; // when len >= VNR_TEXT_CAPACITY
}

static void SpecialHookElf(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  //DWORD arg1 = *(DWORD *)(esp_base + 0x4);
  DWORD arg1 = argof(1, esp_base);
  DWORD arg2_scene = arg1 + 4*5,
        arg2_chara = arg1 + 4*10;
  DWORD text; //= 0; // This variable will be killed
  if (*(DWORD *)arg2_scene == 0) {
    text = *(DWORD *)(arg2_scene + 0xc);
    if (!text || ::IsBadReadPtr((LPCVOID)text, 1)) // Text from scenario could be bad when open backlog while the character is speaking
      return;
    *split = 1;
  } else if (*(DWORD *)arg2_chara == 0) {
    text = arg2_chara + 0xc;
    *split = 2;
  } else
    return;
  //if (text && text < MemDbg::UserMemoryStopAddress) {
  *len = _elf_strlen((LPCSTR)text); // in case the text is bad but still readable
  //*len = ::strlen((LPCSTR)text);
  *data = text;
}

/**
 *  jichi 5/31/2014: elf's
 *  Type1: SEXティーチャー剛史 trial, reladdr = 0x2f0f0, 2 parameters
 *  Type2: 愛姉妹4, reladdr = 0x2f9b0, 3 parameters
 *
 *  IDA: sub_42F9B0 proc near ; bp-based frame
 *    var_8 = dword ptr -8
 *    var_4 = byte ptr -4
 *    var_3 = word ptr -3
 *    arg_0 = dword ptr  8
 *    arg_4 = dword ptr  0Ch
 *    arg_8 = dword ptr  10h
 *
 *  Call graph (Type2):
 *  0x2f9b0 ;  hook here
 *  > 0x666a0 ; called multiple time
 *  > TextOutA ; there are two TextOutA, the second is the right one
 *
 *  Function starts (Type1), pattern offset: 0xc
 *  - 012ef0f0  /$ 55             push ebp ; jichi: hook
 *  - 012ef0f1  |. 8bec           mov ebp,esp
 *  - 012ef0f3  |. 83ec 10        sub esp,0x10
 *  - 012ef0f6  |. 837d 0c 00     cmp dword ptr ss:[ebp+0xc],0x0
 *  - 012ef0fa  |. 53             push ebx
 *  - 012ef0fb  |. 56             push esi
 *  - 012ef0fc  |. 75 0f          jnz short stt_tria.012ef10d ; jicchi: pattern starts
 *  - 012ef0fe  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  - 012ef101  |. 8b48 04        mov ecx,dword ptr ds:[eax+0x4]
 *  - 012ef104  |. 8b91 90000000  mov edx,dword ptr ds:[ecx+0x90] ; jichi: pattern stops
 *  - 012ef10a  |. 8955 0c        mov dword ptr ss:[ebp+0xc],edx
 *  - 012ef10d  |> 8b4d 08        mov ecx,dword ptr ss:[ebp+0x8]
 *  - 012ef110  |. 8b51 04        mov edx,dword ptr ds:[ecx+0x4]
 *  - 012ef113  |. 33c0           xor eax,eax
 *  - 012ef115  |. c645 f8 00     mov byte ptr ss:[ebp-0x8],0x0
 *  - 012ef119  |. 66:8945 f9     mov word ptr ss:[ebp-0x7],ax
 *  - 012ef11d  |. 8b82 b0000000  mov eax,dword ptr ds:[edx+0xb0]
 *  - 012ef123  |. 8945 f4        mov dword ptr ss:[ebp-0xc],eax
 *  - 012ef126  |. 33db           xor ebx,ebx
 *  - 012ef128  |> 8b4f 20        /mov ecx,dword ptr ds:[edi+0x20]
 *  - 012ef12b  |. 83f9 10        |cmp ecx,0x10
 *
 *  Function starts (Type2), pattern offset: 0x10
 *  - 0093f9b0  /$ 55             push ebp  ; jichi: hook here
 *  - 0093f9b1  |. 8bec           mov ebp,esp
 *  - 0093f9b3  |. 83ec 08        sub esp,0x8
 *  - 0093f9b6  |. 837d 10 00     cmp dword ptr ss:[ebp+0x10],0x0
 *  - 0093f9ba  |. 53             push ebx
 *  - 0093f9bb  |. 8b5d 0c        mov ebx,dword ptr ss:[ebp+0xc]
 *  - 0093f9be  |. 56             push esi
 *  - 0093f9bf  |. 57             push edi
 *  - 0093f9c0  |. 75 0f          jnz short silkys.0093f9d1 ; jichi: pattern starts
 *  - 0093f9c2  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  - 0093f9c5  |. 8b48 04        mov ecx,dword ptr ds:[eax+0x4]
 *  - 0093f9c8  |. 8b91 90000000  mov edx,dword ptr ds:[ecx+0x90] ; jichi: pattern stops
 *  - 0093f9ce  |. 8955 10        mov dword ptr ss:[ebp+0x10],edx
 *  - 0093f9d1  |> 33c0           xor eax,eax
 *  - 0093f9d3  |. c645 fc 00     mov byte ptr ss:[ebp-0x4],0x0
 *  - 0093f9d7  |. 66:8945 fd     mov word ptr ss:[ebp-0x3],ax
 *  - 0093f9db  |. 33ff           xor edi,edi
 *  - 0093f9dd  |> 8b53 20        /mov edx,dword ptr ds:[ebx+0x20]
 *  - 0093f9e0  |. 8d4b 0c        |lea ecx,dword ptr ds:[ebx+0xc]
 *  - 0093f9e3  |. 83fa 10        |cmp edx,0x10
 */
bool InsertElfHook()
{
  const BYTE bytes[] = {
      //0x55,                             // 0093f9b0  /$ 55             push ebp  ; jichi: hook here
      //0x8b,0xec,                        // 0093f9b1  |. 8bec           mov ebp,esp
      //0x83,0xec, 0x08,                  // 0093f9b3  |. 83ec 08        sub esp,0x8
      //0x83,0x7d, 0x10, 0x00,            // 0093f9b6  |. 837d 10 00     cmp dword ptr ss:[ebp+0x10],0x0
      //0x53,                             // 0093f9ba  |. 53             push ebx
      //0x8b,0x5d, 0x0c,                  // 0093f9bb  |. 8b5d 0c        mov ebx,dword ptr ss:[ebp+0xc]
      //0x56,                             // 0093f9be  |. 56             push esi
      //0x57,                             // 0093f9bf  |. 57             push edi
      0x75, 0x0f,                       // 0093f9c0  |. 75 0f          jnz short silkys.0093f9d1
      0x8b,0x45, 0x08,                  // 0093f9c2  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
      0x8b,0x48, 0x04,                  // 0093f9c5  |. 8b48 04        mov ecx,dword ptr ds:[eax+0x4]
      0x8b,0x91, 0x90,0x00,0x00,0x00    // 0093f9c8  |. 8b91 90000000  mov edx,dword ptr ds:[ecx+0x90]
  };
  //enum { hook_offset = 0xc };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr);
  //addr = 0x42f170; // 愛姉妹4 Trial
  //reladdr = 0x2f9b0; // 愛姉妹4
  //reladdr = 0x2f0f0; // SEXティーチャー剛史 trial
  if (!addr) {
    ConsoleOutput("vnreng:Elf: pattern not found");
    return false;
  }

  enum : BYTE { push_ebp = 0x55 };
  for (int i = 0; i < 0x20; i++, addr--) // value of i is supposed to be 0xc or 0x10
    if (*(BYTE *)addr == push_ebp) { // beginning of the function

      HookParam hp = {};
      hp.addr = addr;
      hp.text_fun = SpecialHookElf;
      hp.type = USING_STRING|NO_CONTEXT; // = 9

      ConsoleOutput("vnreng: INSERT Elf");
      NewHook(hp, L"Elf");
      return true;
    }
  ConsoleOutput("vnreng:Elf: function not found");
  return false;
}

/** jichi 6/1/2014 Eushully
 *  Insert to the last GetTextExtentPoint32A
 */
bool InsertEushullyHook()
{
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:Eushully: failed to get memory range");
    return false;
  }
  ULONG addr = MemDbg::findLastCallerAddressAfterInt3((DWORD)::GetTextExtentPoint32A, startAddress, stopAddress);
  //ITH_GROWL_DWORD(addr);
  if (!addr) {
    ConsoleOutput("vnreng:Eushully: failed");
    return false;
  }

  // BOOL GetTextExtentPoint32(
  //   _In_   HDC hdc,
  //   _In_   LPCTSTR lpString,
  //   _In_   int c,
  //   _Out_  LPSIZE lpSize
  // );
  enum stack { // current stack
    //retaddr = 0 // esp[0] is the return address since this is the beginning of the function
    arg1_hdc = 4 * 1 // 0x4
    , arg2_lpString = 4 * 2 // 0x8
    , arg3_lc = 4 * 3 // 0xc
    , arg4_lpSize = 4 * 4 // 0x10
  };

  HookParam hp = {};
  hp.addr = addr;
  hp.type = USING_STRING|FIXING_SPLIT; // merging all threads
  hp.off = arg2_lpString; // arg2 = 0x4 * 2
  ConsoleOutput("vnreng: INSERT Eushully");
  NewHook(hp, L"Eushully");
  return true;
}

/** jichi 6/1/2014 AMUSE CRAFT
 *  Related brands: http://erogetrailers.com/brand/2047
 *  Sample game: 魔女こいにっき
 *  See:  http://sakuradite.com/topic/223
 *  Sample H-code: /HBN-4*0:18@26159:MAJOKOI_try.exe (need remove context, though)
 *
 *  Sample games:
 *  - 時計仕掛けのレイライン
 *  - きみと僕との騎士の日々
 *
 *  /HBN-4*0:18@26159:MAJOKOI_TRY.EXE
 *  - addr: 155993
 *  - length_offset: 1
 *  - module: 104464j455
 *  - off: 4294967288 = 0xfffffff8
 *  - split: 24 = 0x18
 *  - type: 1112 = 0x458
 *
 *  Call graph:
 *  - hook reladdr:  0x26159, fun reladdr: 26150
 *  - scene fun reladdr: 0x26fd0
 *    - arg1 and arg3 are pointers
 *    - arg2 is the text
 *  - scneairo only reladdr: 0x26670
 *  Issue for implementing embeded engine: two functions are needed to be hijacked
 *
 *  013c614e     cc             int3
 *  013c614f     cc             int3
 *  013c6150  /$ 55             push ebp ; jichi: function starts
 *  013c6151  |. 8bec           mov ebp,esp
 *  013c6153  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  013c6156  |. 0fb608         movzx ecx,byte ptr ds:[eax]
 *  013c6159  |. 81f9 81000000  cmp ecx,0x81 ; jichi: hook here
 *  013c615f  |. 7c 0d          jl short majokoi_.013c616e
 *  013c6161  |. 8b55 08        mov edx,dword ptr ss:[ebp+0x8]
 *  013c6164  |. 0fb602         movzx eax,byte ptr ds:[edx]
 *  013c6167  |. 3d 9f000000    cmp eax,0x9f
 *  013c616c  |. 7e 1c          jle short majokoi_.013c618a
 *  013c616e  |> 8b4d 08        mov ecx,dword ptr ss:[ebp+0x8]
 *  013c6171  |. 0fb611         movzx edx,byte ptr ds:[ecx]
 *  013c6174  |. 81fa e0000000  cmp edx,0xe0
 *  013c617a  |. 7c 30          jl short majokoi_.013c61ac
 *  013c617c  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  013c617f  |. 0fb608         movzx ecx,byte ptr ds:[eax]
 *  013c6182  |. 81f9 fc000000  cmp ecx,0xfc
 *  013c6188  |. 7f 22          jg short majokoi_.013c61ac
 *  013c618a  |> 8b55 08        mov edx,dword ptr ss:[ebp+0x8]
 *  013c618d  |. 0fb642 01      movzx eax,byte ptr ds:[edx+0x1]
 *  013c6191  |. 83f8 40        cmp eax,0x40
 *  013c6194  |. 7c 16          jl short majokoi_.013c61ac
 *  013c6196  |. 8b4d 08        mov ecx,dword ptr ss:[ebp+0x8]
 *  013c6199  |. 0fb651 01      movzx edx,byte ptr ds:[ecx+0x1]
 *  013c619d  |. 81fa fc000000  cmp edx,0xfc
 *  013c61a3  |. 7f 07          jg short majokoi_.013c61ac
 *  013c61a5  |. b8 01000000    mov eax,0x1
 *  013c61aa  |. eb 02          jmp short majokoi_.013c61ae
 *  013c61ac  |> 33c0           xor eax,eax
 *  013c61ae  |> 5d             pop ebp
 *  013c61af  \. c3             retn
 */
bool InsertAmuseCraftHook()
{
  const BYTE bytes[] = {
    0x55,                 // 013c6150  /$ 55             push ebp ; jichi: function starts
    0x8b,0xec,            // 013c6151  |. 8bec           mov ebp,esp
    0x8b,0x45, 0x08,      // 013c6153  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
    0x0f,0xb6,0x08,       // 013c6156  |. 0fb608         movzx ecx,byte ptr ds:[eax]
    0x81,0xf9 //81000000  // 013c6159  |. 81f9 81000000  cmp ecx,0x81 ; jichi: hook here
  };
  enum { hook_offset = sizeof(bytes) - 2 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(reladdr); // supposed to be 0x21650
  //ITH_GROWL_DWORD(reladdr  + hook_offset);
  //reladdr = 0x26159; // 魔女こいにっき trial
  if (!addr) {
    ConsoleOutput("vnreng:AMUSE CRAFT: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  //hp.type = NO_CONTEXT|USING_SPLIT|DATA_INDIRECT; // 0x418
  //hp.type = NO_CONTEXT|USING_SPLIT|DATA_INDIRECT|RELATIVE_SPLIT;  // Use relative address to prevent floating issue
  hp.type = NO_CONTEXT|USING_SPLIT|DATA_INDIRECT;
  hp.off = -0x8; // eax
  //hp.split = 0x18;
  //hp.split = 0x4; // This is supposed to be the return address
  hp.split = 0x20; // arg6
  hp.length_offset = 1;
  ConsoleOutput("vnreng: INSERT AMUSE CRAFT");
  NewHook(hp, L"AMUSE CRAFT");
  return true;
}

/** jichi 7/6/2014 NeXAS
 *  Sample game: BALDRSKYZERO EXTREME
 *
 *  Call graph:
 *  - GetGlyphOutlineA x 2 functions
 *  - Caller 503620: char = [arg1 + 0x1a8]
 *  - Caller: 500039, 4ffff0
 *    edi = [esi+0x1a0] # stack size 4x3
 *    arg1 = eax = [edi]
 *
 *  0050361f     cc             int3
 *  00503620  /$ 55             push ebp
 *  00503621  |. 8bec           mov ebp,esp
 *  00503623  |. 83e4 f8        and esp,0xfffffff8
 *  00503626  |. 64:a1 00000000 mov eax,dword ptr fs:[0]
 *  0050362c  |. 6a ff          push -0x1
 *  0050362e  |. 68 15815900    push bszex.00598115
 *  00503633  |. 50             push eax
 *  00503634  |. 64:8925 000000>mov dword ptr fs:[0],esp
 *  0050363b  |. 81ec 78010000  sub esp,0x178
 *  00503641  |. 53             push ebx
 *  00503642  |. 8b5d 08        mov ebx,dword ptr ss:[ebp+0x8]
 *  00503645  |. 80bb ed010000 >cmp byte ptr ds:[ebx+0x1ed],0x0
 *  0050364c  |. 56             push esi
 *  0050364d  |. 57             push edi
 *  0050364e  |. 0f85 6e0b0000  jnz bszex.005041c2
 *  00503654  |. 8db3 a8010000  lea esi,dword ptr ds:[ebx+0x1a8]
 *  0050365a  |. c683 ed010000 >mov byte ptr ds:[ebx+0x1ed],0x1
 *  00503661  |. 837e 14 10     cmp dword ptr ds:[esi+0x14],0x10
 *  00503665  |. 72 04          jb short bszex.0050366b
 *  00503667  |. 8b06           mov eax,dword ptr ds:[esi]
 *  00503669  |. eb 02          jmp short bszex.0050366d
 *  0050366b  |> 8bc6           mov eax,esi
 *  0050366d  |> 8038 20        cmp byte ptr ds:[eax],0x20
 *  00503670  |. 0f84 ef0a0000  je bszex.00504165
 *  00503676  |. b9 fcc97400    mov ecx,bszex.0074c9fc
 *  0050367b  |. 8bfe           mov edi,esi
 *  0050367d  |. e8 2e20f1ff    call bszex.004156b0
 *  00503682  |. 84c0           test al,al
 *  00503684  |. 0f85 db0a0000  jnz bszex.00504165
 *  0050368a  |. 8b93 38010000  mov edx,dword ptr ds:[ebx+0x138]
 *  00503690  |. 33c0           xor eax,eax
 *  00503692  |. 3bd0           cmp edx,eax
 *  00503694  |. 0f84 8d0a0000  je bszex.00504127
 *  0050369a  |. 8b8b 3c010000  mov ecx,dword ptr ds:[ebx+0x13c]
 *  005036a0  |. 3bc8           cmp ecx,eax
 *  005036a2  |. 0f84 7f0a0000  je bszex.00504127
 *  005036a8  |. 894424 40      mov dword ptr ss:[esp+0x40],eax
 *  005036ac  |. 894424 44      mov dword ptr ss:[esp+0x44],eax
 *  005036b0  |. 894424 48      mov dword ptr ss:[esp+0x48],eax
 *  005036b4  |. 898424 8c01000>mov dword ptr ss:[esp+0x18c],eax
 *  005036bb  |. 33ff           xor edi,edi
 *  005036bd  |. 66:897c24 60   mov word ptr ss:[esp+0x60],di
 *  005036c2  |. bf 01000000    mov edi,0x1
 *  005036c7  |. 66:897c24 62   mov word ptr ss:[esp+0x62],di
 *  005036cc  |. 33ff           xor edi,edi
 *  005036ce  |. 66:897c24 64   mov word ptr ss:[esp+0x64],di
 *  005036d3  |. 66:897c24 66   mov word ptr ss:[esp+0x66],di
 *  005036d8  |. 66:897c24 68   mov word ptr ss:[esp+0x68],di
 *  005036dd  |. 66:897c24 6a   mov word ptr ss:[esp+0x6a],di
 *  005036e2  |. 66:897c24 6c   mov word ptr ss:[esp+0x6c],di
 *  005036e7  |. bf 01000000    mov edi,0x1
 *  005036ec  |. 66:897c24 6e   mov word ptr ss:[esp+0x6e],di
 *  005036f1  |. 894424 0c      mov dword ptr ss:[esp+0xc],eax
 *  005036f5  |. 894424 10      mov dword ptr ss:[esp+0x10],eax
 *  005036f9  |. 3883 ec010000  cmp byte ptr ds:[ebx+0x1ec],al
 *  005036ff  |. 0f84 39010000  je bszex.0050383e
 *  00503705  |. c78424 f000000>mov dword ptr ss:[esp+0xf0],bszex.00780e>
 *  00503710  |. 898424 3001000>mov dword ptr ss:[esp+0x130],eax
 *  00503717  |. 898424 1001000>mov dword ptr ss:[esp+0x110],eax
 *  0050371e  |. 898424 1401000>mov dword ptr ss:[esp+0x114],eax
 *  00503725  |. c68424 8c01000>mov byte ptr ss:[esp+0x18c],0x1
 *  0050372d  |. 837e 14 10     cmp dword ptr ds:[esi+0x14],0x10
 *  00503731  |. 72 02          jb short bszex.00503735
 *  00503733  |. 8b36           mov esi,dword ptr ds:[esi]
 *  00503735  |> 51             push ecx
 *  00503736  |. 52             push edx
 *  00503737  |. 56             push esi
 *  00503738  |. 8d8424 ec00000>lea eax,dword ptr ss:[esp+0xec]
 *  0050373f  |. 68 00ca7400    push bszex.0074ca00                      ;  ascii "gaiji%s%02d%02d.fil"
 *  00503744  |. 50             push eax
 *  00503745  |. e8 cec6f7ff    call bszex.0047fe18
 *  0050374a  |. 83c4 14        add esp,0x14
 *  0050374d  |. 8d8c24 e000000>lea ecx,dword ptr ss:[esp+0xe0]
 *  00503754  |. 51             push ecx                                 ; /arg1
 *  00503755  |. 8d8c24 9400000>lea ecx,dword ptr ss:[esp+0x94]          ; |
 *  0050375c  |. e8 dfeaefff    call bszex.00402240                      ; \bszex.00402240
 *  00503761  |. 6a 00          push 0x0                                 ; /arg4 = 00000000
 *  00503763  |. 8d9424 9400000>lea edx,dword ptr ss:[esp+0x94]          ; |
 *  0050376a  |. c68424 9001000>mov byte ptr ss:[esp+0x190],0x2          ; |
 *  00503772  |. a1 a8a78200    mov eax,dword ptr ds:[0x82a7a8]          ; |
 *  00503777  |. 52             push edx                                 ; |arg3
 *  00503778  |. 50             push eax                                 ; |arg2 => 00000000
 *  00503779  |. 8d8c24 fc00000>lea ecx,dword ptr ss:[esp+0xfc]          ; |
 *  00503780  |. 51             push ecx                                 ; |arg1
 *  00503781  |. e8 2a0dfeff    call bszex.004e44b0                      ; \bszex.004e44b0
 *  00503786  |. 84c0           test al,al
 *  00503788  |. 8d8c24 9000000>lea ecx,dword ptr ss:[esp+0x90]
 *  0050378f  |. 0f95c3         setne bl
 *  00503792  |. c68424 8c01000>mov byte ptr ss:[esp+0x18c],0x1
 *  0050379a  |. e8 a1baf1ff    call bszex.0041f240
 *  0050379f  |. 84db           test bl,bl
 *  005037a1  |. 74 40          je short bszex.005037e3
 *  005037a3  |. 8db424 f000000>lea esi,dword ptr ss:[esp+0xf0]
 *  005037aa  |. e8 6106feff    call bszex.004e3e10
 *  005037af  |. 8bd8           mov ebx,eax
 *  005037b1  |. 895c24 0c      mov dword ptr ss:[esp+0xc],ebx
 *  005037b5  |. e8 5606feff    call bszex.004e3e10
 *  005037ba  |. 8bf8           mov edi,eax
 *  005037bc  |. 0faffb         imul edi,ebx
 *  005037bf  |. 894424 10      mov dword ptr ss:[esp+0x10],eax
 *  005037c3  |. 8bc7           mov eax,edi
 *  005037c5  |. 8d7424 40      lea esi,dword ptr ss:[esp+0x40]
 *  005037c9  |. e8 e219f1ff    call bszex.004151b0
 *  005037ce  |. 8b5424 40      mov edx,dword ptr ss:[esp+0x40]
 *  005037d2  |. 52             push edx                                 ; /arg1
 *  005037d3  |. 8bc7           mov eax,edi                              ; |
 *  005037d5  |. 8db424 f400000>lea esi,dword ptr ss:[esp+0xf4]          ; |
 *  005037dc  |. e8 8f03feff    call bszex.004e3b70                      ; \bszex.004e3b70
 *  005037e1  |. eb 10          jmp short bszex.005037f3
 *  005037e3  |> 8d8424 e000000>lea eax,dword ptr ss:[esp+0xe0]
 *  005037ea  |. 50             push eax
 *  005037eb  |. e8 60c5f2ff    call bszex.0042fd50
 *  005037f0  |. 83c4 04        add esp,0x4
 *  005037f3  |> 8b5c24 10      mov ebx,dword ptr ss:[esp+0x10]
 *  005037f7  |. 8b7c24 40      mov edi,dword ptr ss:[esp+0x40]
 *  005037fb  |. 8bcb           mov ecx,ebx
 *  005037fd  |. 0faf4c24 0c    imul ecx,dword ptr ss:[esp+0xc]
 *  00503802  |. 33c0           xor eax,eax
 *  00503804  |. 85c9           test ecx,ecx
 *  00503806  |. 7e 09          jle short bszex.00503811
 *  00503808  |> c02c07 02      /shr byte ptr ds:[edi+eax],0x2
 *  0050380c  |. 40             |inc eax
 *  0050380d  |. 3bc1           |cmp eax,ecx
 *  0050380f  |.^7c f7          \jl short bszex.00503808
 *  00503811  |> 8b4d 08        mov ecx,dword ptr ss:[ebp+0x8]
 *  00503814  |. 33c0           xor eax,eax
 *  00503816  |. 8db424 f000000>lea esi,dword ptr ss:[esp+0xf0]
 *  0050381d  |. 8981 dc010000  mov dword ptr ds:[ecx+0x1dc],eax
 *  00503823  |. 8981 e0010000  mov dword ptr ds:[ecx+0x1e0],eax
 *  00503829  |. c78424 f000000>mov dword ptr ss:[esp+0xf0],bszex.00780e>
 *  00503834  |. e8 4702feff    call bszex.004e3a80
 *  00503839  |. e9 68010000    jmp bszex.005039a6
 *  0050383e  |> 8b0d 08a58200  mov ecx,dword ptr ds:[0x82a508]
 *  00503844  |. 51             push ecx                                 ; /hwnd => null
 *  00503845  |. ff15 d4e26f00  call dword ptr ds:[<&user32.getdc>]      ; \getdc
 *  0050384b  |. 68 50b08200    push bszex.0082b050                      ; /facename = ""
 *  00503850  |. 6a 00          push 0x0                                 ; |pitchandfamily = default_pitch|ff_dontcare
 *  00503852  |. 6a 02          push 0x2                                 ; |quality = proof_quality
 *  00503854  |. 6a 00          push 0x0                                 ; |clipprecision = clip_default_precis
 *  00503856  |. 6a 07          push 0x7                                 ; |outputprecision = out_tt_only_precis
 *  00503858  |. 68 80000000    push 0x80                                ; |charset = 128.
 *  0050385d  |. 6a 00          push 0x0                                 ; |strikeout = false
 *  0050385f  |. 6a 00          push 0x0                                 ; |underline = false
 *  00503861  |. 8bf8           mov edi,eax                              ; |
 *  00503863  |. 8b83 38010000  mov eax,dword ptr ds:[ebx+0x138]         ; |
 *  00503869  |. 6a 00          push 0x0                                 ; |italic = false
 *  0050386b  |. 68 84030000    push 0x384                               ; |weight = fw_heavy
 *  00503870  |. 99             cdq                                      ; |
 *  00503871  |. 6a 00          push 0x0                                 ; |orientation = 0x0
 *  00503873  |. 2bc2           sub eax,edx                              ; |
 *  00503875  |. 8b93 3c010000  mov edx,dword ptr ds:[ebx+0x13c]         ; |
 *  0050387b  |. 6a 00          push 0x0                                 ; |escapement = 0x0
 *  0050387d  |. d1f8           sar eax,1                                ; |
 *  0050387f  |. 50             push eax                                 ; |width
 *  00503880  |. 52             push edx                                 ; |height
 *  00503881  |. ff15 48e06f00  call dword ptr ds:[<&gdi32.createfonta>] ; \createfonta
 *  00503887  |. 50             push eax                                 ; /hobject
 *  00503888  |. 57             push edi                                 ; |hdc
 *  00503889  |. 894424 30      mov dword ptr ss:[esp+0x30],eax          ; |
 *  0050388d  |. ff15 4ce06f00  call dword ptr ds:[<&gdi32.selectobject>>; \selectobject
 *  00503893  |. 894424 1c      mov dword ptr ss:[esp+0x1c],eax
 *  00503897  |. 8d8424 4801000>lea eax,dword ptr ss:[esp+0x148]
 *  0050389e  |. 50             push eax                                 ; /ptextmetric
 *  0050389f  |. 57             push edi                                 ; |hdc
 *  005038a0  |. ff15 50e06f00  call dword ptr ds:[<&gdi32.gettextmetric>; \gettextmetricsa
 *  005038a6  |. 837e 14 10     cmp dword ptr ds:[esi+0x14],0x10
 *  005038aa  |. 72 02          jb short bszex.005038ae
 *  005038ac  |. 8b36           mov esi,dword ptr ds:[esi]
 *  005038ae  |> 56             push esi                                 ; /arg1
 *  005038af  |. e8 deccf7ff    call bszex.00480592                      ; \bszex.00480592
 *  005038b4  |. 83c4 04        add esp,0x4
 *  005038b7  |. 8d4c24 60      lea ecx,dword ptr ss:[esp+0x60]
 *  005038bb  |. 51             push ecx                                 ; /pmat2
 *  005038bc  |. 6a 00          push 0x0                                 ; |buffer = null
 *  005038be  |. 6a 00          push 0x0                                 ; |bufsize = 0x0
 *  005038c0  |. 8d9424 d800000>lea edx,dword ptr ss:[esp+0xd8]          ; |
 *  005038c7  |. 52             push edx                                 ; |pmetrics
 *  005038c8  |. 6a 06          push 0x6                                 ; |format = ggo_gray8_bitmap
 *  005038ca  |. 50             push eax                                 ; |char
 *  005038cb  |. 57             push edi                                 ; |hdc
 *  005038cc  |. 894424 30      mov dword ptr ss:[esp+0x30],eax          ; |
 *  005038d0  |. ff15 54e06f00  call dword ptr ds:[<&gdi32.getglyphoutli>; \getglyphoutlinea
 *  005038d6  |. 8bd8           mov ebx,eax
 *  005038d8  |. 85db           test ebx,ebx
 *  005038da  |. 0f84 d5070000  je bszex.005040b5
 *  005038e0  |. 83fb ff        cmp ebx,-0x1
 *  005038e3  |. 0f84 cc070000  je bszex.005040b5
 *  005038e9  |. 8d7424 40      lea esi,dword ptr ss:[esp+0x40]
 *  005038ed  |. e8 be18f1ff    call bszex.004151b0
 *  005038f2  |. 8b4c24 40      mov ecx,dword ptr ss:[esp+0x40]
 *  005038f6  |. 8d4424 60      lea eax,dword ptr ss:[esp+0x60]
 *  005038fa  |. 50             push eax                                 ; /pmat2
 *  005038fb  |. 8b4424 18      mov eax,dword ptr ss:[esp+0x18]          ; |
 *  005038ff  |. 51             push ecx                                 ; |buffer
 *  00503900  |. 53             push ebx                                 ; |bufsize
 *  00503901  |. 8d9424 d800000>lea edx,dword ptr ss:[esp+0xd8]          ; |
 *  00503908  |. 52             push edx                                 ; |pmetrics
 *  00503909  |. 6a 06          push 0x6                                 ; |format = ggo_gray8_bitmap
 *  0050390b  |. 50             push eax                                 ; |char
 *  0050390c  |. 57             push edi                                 ; |hdc
 *  0050390d  |. ff15 54e06f00  call dword ptr ds:[<&gdi32.getglyphoutli>; \getglyphoutlinea
 *  00503913  |. 8b4c24 1c      mov ecx,dword ptr ss:[esp+0x1c]
 *  00503917  |. 51             push ecx                                 ; /hobject
 *  00503918  |. 57             push edi                                 ; |hdc
 *  00503919  |. ff15 4ce06f00  call dword ptr ds:[<&gdi32.selectobject>>; \selectobject
 *  0050391f  |. 8b15 08a58200  mov edx,dword ptr ds:[0x82a508]
 *  00503925  |. 57             push edi                                 ; /hdc
 *  00503926  |. 52             push edx                                 ; |hwnd => null
 *  00503927  |. ff15 a4e26f00  call dword ptr ds:[<&user32.releasedc>]  ; \releasedc
 *  0050392d  |. 8b4424 28      mov eax,dword ptr ss:[esp+0x28]
 *  00503931  |. 50             push eax                                 ; /hobject
 *  00503932  |. ff15 58e06f00  call dword ptr ds:[<&gdi32.deleteobject>>; \deleteobject
 *  00503938  |. 8bb424 cc00000>mov esi,dword ptr ss:[esp+0xcc]
 *  0050393f  |. 8b8c24 d000000>mov ecx,dword ptr ss:[esp+0xd0]
 *  00503946  |. 83c6 03        add esi,0x3
 *  00503949  |. 81e6 fcff0000  and esi,0xfffc
 *  0050394f  |. 8bd1           mov edx,ecx
 *  00503951  |. 0fafd6         imul edx,esi
 *  00503954  |. 897424 0c      mov dword ptr ss:[esp+0xc],esi
 *  00503958  |. 894c24 10      mov dword ptr ss:[esp+0x10],ecx
 *  0050395c  |. 3bda           cmp ebx,edx
 *  0050395e  |. 74 1a          je short bszex.0050397a
 */
bool InsertNeXASHook()
{
  // There are two GetGlyphOutlineA, both of which seem to have the same texts
  ULONG addr = MemDbg::findCallAddress((ULONG)::GetGlyphOutlineA, module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:NexAS: failed");
    return false;
  }

  // DWORD GetGlyphOutline(
  //   _In_   HDC hdc,
  //   _In_   UINT uChar,
  //   _In_   UINT uFormat,
  //   _Out_  LPGLYPHMETRICS lpgm,
  //   _In_   DWORD cbBuffer,
  //   _Out_  LPVOID lpvBuffer,
  //   _In_   const MAT2 *lpmat2
  // );
  enum stack { // current stack
    arg1_hdc = 4 * 0 // starting from 0 before function call
    , arg2_uChar = 4 * 1
    , arg3_uFormat = 4 * 2
    , arg4_lpgm = 4 * 3
    , arg5_cbBuffer = 4 * 4
    , arg6_lpvBuffer = 4 * 5
    , arg7_lpmat2 = 4 * 6
  };

  HookParam hp = {};
  //hp.addr = (DWORD)::GetGlyphOutlineA;
  hp.addr = addr;
  //hp.type = USING_STRING|USING_SPLIT;
  hp.type = BIG_ENDIAN|NO_CONTEXT|USING_SPLIT;
  hp.length_offset = 1; // determine string length at runtime
  hp.off = arg2_uChar; // = 0x4, arg2 before the function call, so it is: 0x4 * (2-1) = 4

  // Either lpgm or lpmat2 are good choices
  hp.split = arg4_lpgm; // = 0xc, arg4
  //hp.split = arg7_lpmat2; // = 0x18, arg7

  ConsoleOutput("vnreng: INSERT NeXAS");
  NewHook(hp, L"NeXAS");
  return true;
}

/** jichi 7/6/2014 YukaSystem2
 *  Sample game: セミラミスの天秤
 *
 *  Observations from Debug:
 *  - Ollydbg got UTF8 text memory address
 *  - Hardware break points have loops on 0x4010ED
 *  - The hooked function seems to take 3 parameters, and arg3 is the right text
 *  - The text appears character by character
 *
 *  Runtime stack:
 *  - return address
 *  - arg1 pointer's pointer
 *  - arg2 text
 *  - arg3 pointer's pointer
 *  - code address or -1, maybe a handle
 *  - unknown pointer
 *  - return address
 *  - usually zero
 *
 *  0040109d     cc             int3
 *  0040109e     cc             int3
 *  0040109f     cc             int3
 *  004010a0  /$ 55             push ebp
 *  004010a1  |. 8bec           mov ebp,esp
 *  004010a3  |. 8b45 14        mov eax,dword ptr ss:[ebp+0x14]
 *  004010a6  |. 50             push eax                                 ; /arg4
 *  004010a7  |. 8b4d 10        mov ecx,dword ptr ss:[ebp+0x10]          ; |
 *  004010aa  |. 51             push ecx                                 ; |arg3
 *  004010ab  |. 8b55 0c        mov edx,dword ptr ss:[ebp+0xc]           ; |
 *  004010ae  |. 52             push edx                                 ; |arg2
 *  004010af  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]           ; |
 *  004010b2  |. 50             push eax                                 ; |arg1
 *  004010b3  |. e8 48ffffff    call semirami.00401000                   ; \semirami.00401000
 *  004010b8  |. 83c4 10        add esp,0x10
 *  004010bb  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  004010be  |. 5d             pop ebp
 *  004010bf  \. c3             retn
 *  004010c0  /$ 55             push ebp
 *  004010c1  |. 8bec           mov ebp,esp
 *  004010c3  |. 8b45 14        mov eax,dword ptr ss:[ebp+0x14]
 *  004010c6  |. 50             push eax                                 ; /arg4
 *  004010c7  |. 8b4d 10        mov ecx,dword ptr ss:[ebp+0x10]          ; |
 *  004010ca  |. 51             push ecx                                 ; |arg3
 *  004010cb  |. 8b55 0c        mov edx,dword ptr ss:[ebp+0xc]           ; |
 *  004010ce  |. 52             push edx                                 ; |arg2
 *  004010cf  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]           ; |
 *  004010d2  |. 50             push eax                                 ; |arg1
 *  004010d3  |. e8 58ffffff    call semirami.00401030                   ; \semirami.00401030
 *  004010d8  |. 83c4 10        add esp,0x10
 *  004010db  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8]
 *  004010de  |. 5d             pop ebp
 *  004010df  \. c3             retn
 *  004010e0  /$ 55             push ebp ; jichi: function begin, hook here, bp-based frame, arg2 is the text
 *  004010e1  |. 8bec           mov ebp,esp
 *  004010e3  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8] ; jichi: ebp+0x8 = arg2
 *  004010e6  |. 8b4d 0c        mov ecx,dword ptr ss:[ebp+0xc] ; jichi: arg3 is also a pointer of pointer
 *  004010e9  |. 8a11           mov dl,byte ptr ds:[ecx]
 *  004010eb  |. 8810           mov byte ptr ds:[eax],dl    ; jichi: eax is the data
 *  004010ed  |. 5d             pop ebp
 *  004010ee  \. c3             retn
 *  004010ef     cc             int3
 */

// Ignore image and music file names
// Sample text: "Voice\tou00012.ogg""運命論って云うのかなあ……神さまを信じてる人が多かったからだろうね、何があっても、それは神さまが自分たちに与えられた試練なんだって、そう思ってたみたい。勿論、今でもそう考えている人はいっぱいいるんだけど。"
// Though the input string is UTF-8, it should be ASCII compatible.
static bool _yk2garbage(const char *p)
{
  //Q_ASSERT(p);
  while (char ch = *p++) {
    if (ch >= '0' && ch <= '9' ||
        ch >= 'A' && ch <= 'z' || // also ignore ASCII 91-96: [ \ ] ^ _ `
        ch == '"' || ch == '.' || ch == '-' || ch == '#')
      continue;
    return false;
  }
  return true;
}

// Get text from arg2
static void SpecialHookYukaSystem2(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD arg2 = argof(2, esp_base), // [esp+0x8]
        arg3 = argof(3, esp_base); // [esp+0xc]
        //arg4 = argof(4, esp_base); // there is no arg4. arg4 is properlly a function pointer
  LPCSTR text = (LPCSTR)arg2;
  if (*text && !_yk2garbage(text)) { // I am sure this could be null
    *data = (DWORD)text;
    *len = ::strlen(text); // UTF-8 is null-terminated
    if (arg3)
      *split = *(DWORD *)arg3;
  }
}

bool InsertYukaSystem2Hook()
{
  const BYTE bytes[] = {
    0x55,            // 004010e0  /$ 55             push ebp ; jichi; hook here
    0x8b,0xec,       // 004010e1  |. 8bec           mov ebp,esp
    0x8b,0x45, 0x08, // 004010e3  |. 8b45 08        mov eax,dword ptr ss:[ebp+0x8] ; jichi: ebp+0x8 = arg2
    0x8b,0x4d, 0x0c, // 004010e6  |. 8b4d 0c        mov ecx,dword ptr ss:[ebp+0xc]
    0x8a,0x11,       // 004010e9  |. 8a11           mov dl,byte ptr ds:[ecx]
    0x88,0x10,       // 004010eb  |. 8810           mov byte ptr ds:[eax],dl    ; jichi: eax is the address to text
    0x5d,            // 004010ed  |. 5d             pop ebp
    0xc3             // 004010ee  \. c3             retn
  };
  //enum { hook_offset = 0 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr); // supposed to be 0x4010e0
  if (!addr) {
    ConsoleOutput("vnreng:YukaSystem2: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.type = NO_CONTEXT|USING_STRING|USING_UTF8; // UTF-8, though
  hp.text_fun = SpecialHookYukaSystem2;
  ConsoleOutput("vnreng: INSERT YukaSystem2");
  NewHook(hp, L"YukaSystem2");
  return true;
}

/** jichi 8/2/2014 2RM
 *  Sample games:
 *  - [エロイット] 父娘愛 ～いけない子作り2～ - /HBN-20*0@54925:oyakoai.exe
 *  - [エロイット] いけない子作り ～親友のお母さんに種付けしまくる1週間～ -- /HS-1C@46FC9D (not used)
 *
 *  Observations from Debug of 父娘愛:
 *  - The executable shows product name as 2RM - Adventure Engine
 *  - 2 calls to GetGlyphOutlineA with incompleted game
 *  - Memory location of the text is fixed
 *  - The LAST place accessing the text is hooked
 *  - The actual text has pattern like this {surface,ruby} and hence not hooked
 *
 *  /HBN-20*0@54925:oyakoai.exe
 *  - addr: 346405 = 0x54925
 *  - length_offset: 1
 *  - module: 3918223605
 *  - off: 4294967260 = 0xffffffdc = -0x24 -- 0x24 comes from  mov ebp,dword ptr ss:[esp+0x24]
 *  - type: 1096 = 0x448
 *
 *  This is a very long function
 *  父娘愛:
 *  - 004548e1  |. 84db           test bl,bl
 *  - 004548e3  |. 8b7424 20      mov esi,dword ptr ss:[esp+0x20]
 *  - 004548e7  |. 74 08          je short oyakoai.004548f1
 *  - 004548e9  |. c74424 24 0000>mov dword ptr ss:[esp+0x24],0x0
 *  - 004548f1  |> 8b6c24 3c      mov ebp,dword ptr ss:[esp+0x3c]
 *  - 004548f5  |. 837d 5c 00     cmp dword ptr ss:[ebp+0x5c],0x0
 *  - 004548f9  |. c74424 18 0000>mov dword ptr ss:[esp+0x18],0x0
 *  - 00454901  |. 0f8e da000000  jle oyakoai.004549e1
 *  - 00454907  |. 8b6c24 24      mov ebp,dword ptr ss:[esp+0x24]
 *  - 0045490b  |. eb 0f          jmp short oyakoai.0045491c
 *  - 0045490d  |  8d49 00        lea ecx,dword ptr ds:[ecx]
 *  - 00454910  |> 8b15 50bd6c00  mov edx,dword ptr ds:[0x6cbd50]
 *  - 00454916  |. 8b0d 94bd6c00  mov ecx,dword ptr ds:[0x6cbd94]
 *  - 0045491c  |> 803f 00        cmp byte ptr ds:[edi],0x0
 *  - 0045491f  |. 0f84 db000000  je oyakoai.00454a00
 *  - 00454925  |. 0fb717         movzx edx,word ptr ds:[edi]   ; jichi: hook here
 *  - 00454928  |. 8b4c24 10      mov ecx,dword ptr ss:[esp+0x10]
 *  - 0045492c  |. 52             push edx
 *  - 0045492d  |. 894c24 2c      mov dword ptr ss:[esp+0x2c],ecx
 *  - 00454931  |. e8 9a980100    call oyakoai.0046e1d0
 *  - 00454936  |. 83c4 04        add esp,0x4
 *  - 00454939  |. 85c0           test eax,eax
 *  - 0045493b  |. 74 50          je short oyakoai.0045498d
 *  - 0045493d  |. 0335 50bd6c00  add esi,dword ptr ds:[0x6cbd50]
 *  - 00454943  |. 84db           test bl,bl
 *  - 00454945  |. 74 03          je short oyakoai.0045494a
 *  - 00454947  |. 83c5 02        add ebp,0x2
 *  - 0045494a  |> 3b7424 1c      cmp esi,dword ptr ss:[esp+0x1c]
 *  - 0045494e  |. a1 54bd6c00    mov eax,dword ptr ds:[0x6cbd54]
 *  - 00454953  |. 7f 12          jg short oyakoai.00454967
 *  - 00454955  |. 84db           test bl,bl
 *  - 00454957  |. 0f84 ea000000  je oyakoai.00454a47
 *  - 0045495d  |. 3b6c24 40      cmp ebp,dword ptr ss:[esp+0x40]
 *  - 00454961  |. 0f85 e0000000  jnz oyakoai.00454a47
 *  - 00454967  |> 014424 10      add dword ptr ss:[esp+0x10],eax
 *  - 0045496b  |. 84db           test bl,bl
 *  - 0045496d  |. 8b7424 20      mov esi,dword ptr ss:[esp+0x20]
 *  - 00454971  |. 0f84 d0000000  je oyakoai.00454a47
 *  - 00454977  |. 3b6c24 40      cmp ebp,dword ptr ss:[esp+0x40]
 *  - 0045497b  |. 0f85 c6000000  jnz oyakoai.00454a47
 *  - 00454981  |. 33ed           xor ebp,ebp
 *  - 00454983  |. 83c7 02        add edi,0x2
 *  - 00454986  |. 834424 18 01   add dword ptr ss:[esp+0x18],0x1
 *  - 0045498b  |. eb 3c          jmp short oyakoai.004549c9
 *  - 0045498d  |> a1 50bd6c00    mov eax,dword ptr ds:[0x6cbd50]
 *  - 00454992  |. d1e8           shr eax,1
 *  - 00454994  |. 03f0           add esi,eax
 *  - 00454996  |. 84db           test bl,bl
 *  - 00454998  |. 74 03          je short oyakoai.0045499d
 *  - 0045499a  |. 83c5 01        add ebp,0x1
 *  - 0045499d  |> 3b7424 1c      cmp esi,dword ptr ss:[esp+0x1c]
 *  - 004549a1  |. a1 54bd6c00    mov eax,dword ptr ds:[0x6cbd54]
 *  - 004549a6  |. 7f 0a          jg short oyakoai.004549b2
 *  - 004549a8  |. 84db           test bl,bl
 *
 *  いけない子作り:
 *  00454237   c74424 24 020000>mov dword ptr ss:[esp+0x24],0x2
 *  0045423f   3bf5             cmp esi,ebp
 *  00454241   7f 0e            jg short .00454251
 *  00454243   84db             test bl,bl
 *  00454245   74 1e            je short .00454265
 *  00454247   8b6c24 24        mov ebp,dword ptr ss:[esp+0x24]
 *  0045424b   3b6c24 40        cmp ebp,dword ptr ss:[esp+0x40]
 *  0045424f   75 14            jnz short .00454265
 *  00454251   014424 10        add dword ptr ss:[esp+0x10],eax
 *  00454255   84db             test bl,bl
 *  00454257   8b7424 20        mov esi,dword ptr ss:[esp+0x20]
 *  0045425b   74 08            je short .00454265
 *  0045425d   c74424 24 000000>mov dword ptr ss:[esp+0x24],0x0
 *  00454265   8b6c24 3c        mov ebp,dword ptr ss:[esp+0x3c]
 *  00454269   837d 5c 00       cmp dword ptr ss:[ebp+0x5c],0x0
 *  0045426d   c74424 18 000000>mov dword ptr ss:[esp+0x18],0x0
 *  00454275   0f8e d7000000    jle .00454352
 *  0045427b   8b6c24 24        mov ebp,dword ptr ss:[esp+0x24]
 *  0045427f   eb 0c            jmp short .0045428d
 *  00454281   8b15 18ad6c00    mov edx,dword ptr ds:[0x6cad18]
 *  00454287   8b0d 5cad6c00    mov ecx,dword ptr ds:[0x6cad5c]
 *  0045428d   803f 00          cmp byte ptr ds:[edi],0x0
 *  00454290   0f84 db000000    je .00454371
 *  00454296   0fb717           movzx edx,word ptr ds:[edi] ; jichi: hook here
 *  00454299   8b4c24 10        mov ecx,dword ptr ss:[esp+0x10]
 *  0045429d   52               push edx
 *  0045429e   894c24 2c        mov dword ptr ss:[esp+0x2c],ecx
 *  004542a2   e8 498a0100      call .0046ccf0
 *  004542a7   83c4 04          add esp,0x4
 *  004542aa   85c0             test eax,eax
 *  004542ac   74 50            je short .004542fe
 *  004542ae   0335 18ad6c00    add esi,dword ptr ds:[0x6cad18]
 *  004542b4   84db             test bl,bl
 *  004542b6   74 03            je short .004542bb
 *  004542b8   83c5 02          add ebp,0x2
 *  004542bb   3b7424 1c        cmp esi,dword ptr ss:[esp+0x1c]
 *  004542bf   a1 1cad6c00      mov eax,dword ptr ds:[0x6cad1c]
 *  004542c4   7f 12            jg short .004542d8
 *  004542c6   84db             test bl,bl
 *  004542c8   0f84 ea000000    je .004543b8
 *  004542ce   3b6c24 40        cmp ebp,dword ptr ss:[esp+0x40]
 *  004542d2   0f85 e0000000    jnz .004543b8
 *  004542d8   014424 10        add dword ptr ss:[esp+0x10],eax
 *  004542dc   84db             test bl,bl
 *  004542de   8b7424 20        mov esi,dword ptr ss:[esp+0x20]
 *  004542e2   0f84 d0000000    je .004543b8
 *  004542e8   3b6c24 40        cmp ebp,dword ptr ss:[esp+0x40]
 *  004542ec   0f85 c6000000    jnz .004543b8
 *  004542f2   33ed             xor ebp,ebp
 *  004542f4   83c7 02          add edi,0x2
 *  004542f7   834424 18 01     add dword ptr ss:[esp+0x18],0x1
 *  004542fc   eb 3c            jmp short .0045433a
 *  004542fe   a1 18ad6c00      mov eax,dword ptr ds:[0x6cad18]
 *  00454303   d1e8             shr eax,1
 *  00454305   03f0             add esi,eax
 *  00454307   84db             test bl,bl
 *  00454309   74 03            je short .0045430e
 *  0045430b   83c5 01          add ebp,0x1
 */
bool Insert2RMHook()
{
  const BYTE bytes[] = {
    0x80,0x3f, 0x00,                // 0045428d   803f 00          cmp byte ptr ds:[edi],0x0
    0x0f,0x84, 0xdb,0x00,0x00,0x00, // 00454290   0f84 db000000    je .00454371
    0x0f,0xb7,0x17,                 // 00454296   0fb717           movzx edx,word ptr ds:[edi] ; jichi: hook here
    0x8b,0x4c,0x24, 0x10,           // 00454299   8b4c24 10        mov ecx,dword ptr ss:[esp+0x10]
    0x52,                           // 0045429d   52               push edx
    0x89,0x4c,0x24, 0x2c,           // 0045429e   894c24 2c        mov dword ptr ss:[esp+0x2c],ecx
    0xe8 //, 498a0100               // 004542a2   e8 498a0100      call .0046ccf0
  };
  enum { hook_offset = 0x00454296 - 0x0045428d };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr); // supposed to be 0x4010e0
  if (!addr) {
    ConsoleOutput("vnreng:2RM: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.length_offset = 1;
  hp.off = -0x24;
  hp.type = NO_CONTEXT|DATA_INDIRECT;
  ConsoleOutput("vnreng: INSERT 2RM");
  NewHook(hp, L"2RM");
  return true;
}

/** jichi 8/2/2014 side-B
 *  Sample games:
 *  - [side-B] メルトピア -- /HS-4@B4452:Martopia.exe
 *
 *  Observations:
 *
 *  /HS-4@B4452:Martopia.exe
 *  - addr: 738386 = 0xb4452
 *  - module: 3040177000
 *  - off: 4294967288 = 0xfffffff8 = -0x8
 *  - type: 65 = 0x41
 *
 *  Sample stack structure:
 *  - 0016F558   00EB74E9  RETURN to Martopia.00EB74E9
 *  - 0016F55C   0060EE30 ; jichi: this is the text
 *  - 0016F560   0016F5C8
 *  - 0016F564   082CAA98
 *  - 0016F568   00EBE735  RETURN to Martopia.00EBE735 from Martopia.00EB74C0
 *
 *  00f6440e   cc               int3
 *  00f6440f   cc               int3
 *  00f64410   55               push ebp    ; jichi: hook here, text in arg1 ([EncodeSystemPointer(+4])
 *  00f64411   8bec             mov ebp,esp
 *  00f64413   6a ff            push -0x1
 *  00f64415   68 c025fb00      push martopia.00fb25c0
 *  00f6441a   64:a1 00000000   mov eax,dword ptr fs:[0]
 *  00f64420   50               push eax
 *  00f64421   83ec 3c          sub esp,0x3c
 *  00f64424   a1 c8620101      mov eax,dword ptr ds:[0x10162c8]
 *  00f64429   33c5             xor eax,ebp
 *  00f6442b   8945 f0          mov dword ptr ss:[ebp-0x10],eax
 *  00f6442e   53               push ebx
 *  00f6442f   56               push esi
 *  00f64430   57               push edi
 *  00f64431   50               push eax
 *  00f64432   8d45 f4          lea eax,dword ptr ss:[ebp-0xc]
 *  00f64435   64:a3 00000000   mov dword ptr fs:[0],eax
 *  00f6443b   8bf9             mov edi,ecx
 *  00f6443d   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 *  00f64440   33db             xor ebx,ebx
 *  00f64442   3bcb             cmp ecx,ebx
 *  00f64444   74 40            je short martopia.00f64486
 *  00f64446   8bc1             mov eax,ecx
 *  00f64448   c745 e8 0f000000 mov dword ptr ss:[ebp-0x18],0xf
 *  00f6444f   895d e4          mov dword ptr ss:[ebp-0x1c],ebx
 *  00f64452   885d d4          mov byte ptr ss:[ebp-0x2c],bl   ; jichi: or hook here, get text in eax
 *  00f64455   8d70 01          lea esi,dword ptr ds:[eax+0x1]
 *  00f64458   8a10             mov dl,byte ptr ds:[eax]
 *  00f6445a   40               inc eax
 *  00f6445b   3ad3             cmp dl,bl
 *  00f6445d  ^75 f9            jnz short martopia.00f64458
 *  00f6445f   2bc6             sub eax,esi
 *  00f64461   50               push eax
 *  00f64462   51               push ecx
 *  00f64463   8d4d d4          lea ecx,dword ptr ss:[ebp-0x2c]
 *  00f64466   e8 f543f5ff      call martopia.00eb8860
 *  00f6446b   8d45 d4          lea eax,dword ptr ss:[ebp-0x2c]
 *  00f6446e   50               push eax
 *  00f6446f   8d4f 3c          lea ecx,dword ptr ds:[edi+0x3c]
 *  00f64472   895d fc          mov dword ptr ss:[ebp-0x4],ebx
 *  00f64475   e8 16d7f8ff      call martopia.00ef1b90
 *  00f6447a   837d e8 10       cmp dword ptr ss:[ebp-0x18],0x10
 *  00f6447e   72 47            jb short martopia.00f644c7
 *  00f64480   8b4d d4          mov ecx,dword ptr ss:[ebp-0x2c]
 *  00f64483   51               push ecx
 *  00f64484   eb 38            jmp short martopia.00f644be
 *  00f64486   53               push ebx
 *  00f64487   68 a11efd00      push martopia.00fd1ea1
 *  00f6448c   8d4d b8          lea ecx,dword ptr ss:[ebp-0x48]
 *  00f6448f   c745 cc 0f000000 mov dword ptr ss:[ebp-0x34],0xf
 *  00f64496   895d c8          mov dword ptr ss:[ebp-0x38],ebx
 *  00f64499   885d b8          mov byte ptr ss:[ebp-0x48],bl
 *  00f6449c   e8 bf43f5ff      call martopia.00eb8860
 *  00f644a1   8d55 b8          lea edx,dword ptr ss:[ebp-0x48]
 *  00f644a4   52               push edx
 *  00f644a5   8d4f 3c          lea ecx,dword ptr ds:[edi+0x3c]
 *  00f644a8   c745 fc 01000000 mov dword ptr ss:[ebp-0x4],0x1
 *  00f644af   e8 dcd6f8ff      call martopia.00ef1b90
 *  00f644b4   837d cc 10       cmp dword ptr ss:[ebp-0x34],0x10
 *  00f644b8   72 0d            jb short martopia.00f644c7
 *  00f644ba   8b45 b8          mov eax,dword ptr ss:[ebp-0x48]
 *  00f644bd   50               push eax
 *  00f644be   ff15 f891fc00    call dword ptr ds:[<&msvcr100.??3@yaxpax>; msvcr100.??3@yaxpax@z
 *  00f644c4   83c4 04          add esp,0x4
 *  00f644c7   8b4d f4          mov ecx,dword ptr ss:[ebp-0xc]
 *  00f644ca   64:890d 00000000 mov dword ptr fs:[0],ecx
 *  00f644d1   59               pop ecx
 *  00f644d2   5f               pop edi
 *  00f644d3   5e               pop esi
 *  00f644d4   5b               pop ebx
 *  00f644d5   8b4d f0          mov ecx,dword ptr ss:[ebp-0x10]
 *  00f644d8   33cd             xor ecx,ebp
 *  00f644da   e8 77510400      call martopia.00fa9656
 *  00f644df   8be5             mov esp,ebp
 *  00f644e1   5d               pop ebp
 *  00f644e2   c2 0400          retn 0x4
 *  00f644e5   cc               int3
 *  00f644e6   cc               int3
 */
bool InsertSideBHook()
{
  const BYTE bytes[] = {
    0x64,0xa3, 0x00,0x00,0x00,0x00,       // 00f64435   64:a3 00000000   mov dword ptr fs:[0],eax
    0x8b,0xf9,                            // 00f6443b   8bf9             mov edi,ecx
    0x8b,0x4d, 0x08,                      // 00f6443d   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
    0x33,0xdb,                            // 00f64440   33db             xor ebx,ebx
    0x3b,0xcb,                            // 00f64442   3bcb             cmp ecx,ebx
    0x74, 0x40,                           // 00f64444   74 40            je short martopia.00f64486
    0x8b,0xc1,                            // 00f64446   8bc1             mov eax,ecx
    0xc7,0x45, 0xe8, 0x0f,0x00,0x00,0x00, // 00f64448   c745 e8 0f000000 mov dword ptr ss:[ebp-0x18],0xf
    0x89,0x5d, 0xe4,                      // 00f6444f   895d e4          mov dword ptr ss:[ebp-0x1c],ebx
    0x88,0x5d, 0xd4                       // 00f64452   885d d4          mov byte ptr ss:[ebp-0x2c],bl
  };
  enum { hook_offset = 0x00f64410 - 0x00f64435 }; // distance to the beginning of the function
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr); // supposed to be 0x4010e0
  if (!addr) {
    ConsoleOutput("vnreng:SideB: pattern not found");
    return false;
  }
  addr += hook_offset;
  enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
  if (*(BYTE *)addr != push_ebp) {
    ConsoleOutput("vnreng:SideB: pattern found but the function offset is invalid");
    return false;
  }
  //ITH_GROWL_DWORD(addr);

  HookParam hp = {};
  hp.addr = addr;
  //hp.length_offset = 1;
  hp.off = 4; // [esp+4] == arg1
  hp.type = USING_STRING|NO_CONTEXT|USING_SPLIT|RELATIVE_SPLIT; // NO_CONTEXT && RELATIVE_SPLIT to get rid of floating return address
  //hp.split = 0; // use retaddr as split
  ConsoleOutput("vnreng: INSERT SideB");
  NewHook(hp, L"SideB");
  return true;
}

/** jichi 9/8/2014 EXP, http://www.exp-inc.jp
 *  Maker: EXP, 5pb
 *  Sample game: 剣の街の異邦人
 *
 *  There are three matched memory addresses with SHIFT-JIS.
 *  The middle one is used as it is aligned with zeros.
 *  The memory address is fixed.
 *
 *  There are three functions found using hardware breakpoints.
 *  The last one is used as the first two are looped.
 *
 *  reladdr = 0x138020
 *
 *  baseaddr = 0x00120000
 *
 *  0025801d   cc               int3
 *  0025801e   cc               int3
 *  0025801f   cc               int3
 *  00258020   55               push ebp  ; jichi: hook here
 *  00258021   8bec             mov ebp,esp
 *  00258023   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  00258026   83ec 08          sub esp,0x8
 *  00258029   85c0             test eax,eax
 *  0025802b   0f84 d8000000    je .00258109
 *  00258031   837d 10 00       cmp dword ptr ss:[ebp+0x10],0x0
 *  00258035   0f84 ce000000    je .00258109
 *  0025803b   8b10             mov edx,dword ptr ds:[eax]      ; jichi: edx is the text
 *  0025803d   8b45 0c          mov eax,dword ptr ss:[ebp+0xc]
 *  00258040   53               push ebx
 *  00258041   56               push esi
 *  00258042   c745 f8 00000000 mov dword ptr ss:[ebp-0x8],0x0
 *  00258049   8945 fc          mov dword ptr ss:[ebp-0x4],eax
 *  0025804c   57               push edi
 *  0025804d   8d49 00          lea ecx,dword ptr ds:[ecx]
 *  00258050   8a0a             mov cl,byte ptr ds:[edx]    jichi: text in accessed in edx
 *  00258052   8a45 14          mov al,byte ptr ss:[ebp+0x14]
 *  00258055   3ac1             cmp al,cl
 *  00258057   74 7a            je short .002580d3
 *  00258059   8b7d 10          mov edi,dword ptr ss:[ebp+0x10]
 *  0025805c   8b5d fc          mov ebx,dword ptr ss:[ebp-0x4]
 *  0025805f   33f6             xor esi,esi
 *  00258061   8bc2             mov eax,edx
 *  00258063   80f9 81          cmp cl,0x81
 *  00258066   72 05            jb short .0025806d
 *  00258068   80f9 9f          cmp cl,0x9f
 *  0025806b   76 0a            jbe short .00258077
 *  0025806d   80f9 e0          cmp cl,0xe0
 *  00258070   72 1d            jb short .0025808f
 *  00258072   80f9 fc          cmp cl,0xfc
 *  00258075   77 18            ja short .0025808f
 *  00258077   8b45 fc          mov eax,dword ptr ss:[ebp-0x4]
 *  0025807a   85c0             test eax,eax
 *  0025807c   74 05            je short .00258083
 *  0025807e   8808             mov byte ptr ds:[eax],cl
 *  00258080   8d58 01          lea ebx,dword ptr ds:[eax+0x1]
 *  00258083   8b7d 10          mov edi,dword ptr ss:[ebp+0x10]
 *  00258086   8d42 01          lea eax,dword ptr ds:[edx+0x1]
 *  00258089   be 01000000      mov esi,0x1
 *  0025808e   4f               dec edi
 *  0025808f   85ff             test edi,edi
 *  00258091   74 36            je short .002580c9
 *  00258093   85db             test ebx,ebx
 *  00258095   74 04            je short .0025809b
 *  00258097   8a08             mov cl,byte ptr ds:[eax]
 *  00258099   880b             mov byte ptr ds:[ebx],cl
 *  0025809b   46               inc esi
 *  0025809c   33c0             xor eax,eax
 *  0025809e   66:3bc6          cmp ax,si
 *  002580a1   7f 47            jg short .002580ea
 *  002580a3   0fbfce           movsx ecx,si
 *  002580a6   03d1             add edx,ecx
 *  002580a8   3945 fc          cmp dword ptr ss:[ebp-0x4],eax
 *  002580ab   74 03            je short .002580b0
 *  002580ad   014d fc          add dword ptr ss:[ebp-0x4],ecx
 *  002580b0   294d 10          sub dword ptr ss:[ebp+0x10],ecx
 *  002580b3   014d f8          add dword ptr ss:[ebp-0x8],ecx
 *  002580b6   8a0a             mov cl,byte ptr ds:[edx]
 *  002580b8   80f9 0a          cmp cl,0xa
 *  002580bb   74 20            je short .002580dd
 *  002580bd   80f9 0d          cmp cl,0xd
 *  002580c0   74 1b            je short .002580dd
 *  002580c2   3945 10          cmp dword ptr ss:[ebp+0x10],eax
 *  002580c5  ^75 89            jnz short .00258050
 *  002580c7   eb 21            jmp short .002580ea
 *  002580c9   85db             test ebx,ebx
 *  002580cb   74 1d            je short .002580ea
 *  002580cd   c643 ff 00       mov byte ptr ds:[ebx-0x1],0x0
 *  002580d1   eb 17            jmp short .002580ea
 *  002580d3   84c0             test al,al
 *  002580d5   74 13            je short .002580ea
 *  002580d7   42               inc edx
 *  002580d8   ff45 f8          inc dword ptr ss:[ebp-0x8]
 *  002580db   eb 0d            jmp short .002580ea
 *  002580dd   8a42 01          mov al,byte ptr ds:[edx+0x1]
 *  002580e0   42               inc edx
 *  002580e1   3c 0a            cmp al,0xa
 *  002580e3   74 04            je short .002580e9
 *  002580e5   3c 0d            cmp al,0xd
 *  002580e7   75 01            jnz short .002580ea
 *  002580e9   42               inc edx
 *  002580ea   8b45 fc          mov eax,dword ptr ss:[ebp-0x4]
 *  002580ed   5f               pop edi
 *  002580ee   5e               pop esi
 *  002580ef   5b               pop ebx
 *  002580f0   85c0             test eax,eax
 *  002580f2   74 09            je short .002580fd
 *  002580f4   837d 10 00       cmp dword ptr ss:[ebp+0x10],0x0
 *  002580f8   74 03            je short .002580fd
 *  002580fa   c600 00          mov byte ptr ds:[eax],0x0
 *  002580fd   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 *  00258100   8b45 f8          mov eax,dword ptr ss:[ebp-0x8]
 *  00258103   8911             mov dword ptr ds:[ecx],edx
 *  00258105   8be5             mov esp,ebp
 *  00258107   5d               pop ebp
 *  00258108   c3               retn
 *  00258109   33c0             xor eax,eax
 *  0025810b   8be5             mov esp,ebp
 *  0025810d   5d               pop ebp
 *  0025810e   c3               retn
 *  0025810f   cc               int3
 *
 *  Stack:
 *  0f14f87c   00279177  return to .00279177 from .00258020
 *  0f14f880   0f14f8b0 ; arg1  address of the text's pointer
 *  0f14f884   0f14f8c0 ; arg2  pointed to zero, maybe a buffer
 *  0f14f888   00000047 ; arg3  it is zero if no text, this value might be text size + 1
 *  0f14f88c   ffffff80 ; constant, used as split
 *  0f14f890   005768c8  .005768c8
 *  0f14f894   02924340 ; text is at 02924350
 *  0f14f898   00000001 ; this might also be a good split
 *  0f14f89c   1b520020
 *  0f14f8a0   00000000
 *  0f14f8a4   00000000
 *  0f14f8a8   029245fc
 *  0f14f8ac   0004bfd3
 *  0f14f8b0   0f14fae0
 *  0f14f8b4   00000000
 *  0f14f8b8   00000000
 *  0f14f8bc   02924340
 *  0f14f8c0   00000000
 *
 *  Registers:
 *  eax 0f14f8c0 ; floating at runtime
 *  ecx 0f14f8b0; floating at runtime
 *  edx 00000000
 *  ebx 0f14fae0; floating at runtime
 *  esp 0f14f87c; floating at runtime
 *  ebp 0f14facc; floating at runtime
 *  esi 00000047
 *  edi 02924340 ; text is in 02924350
 *  eip 00258020 .00258020
 *
 *  Memory access pattern:
 *  For long sentences, it first render the first line, then the second line, and so on.
 *  So, the second line is a subtext of the entire dialog.
 */
static void SpecialHookExp(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  static DWORD lasttext;
  // 00258020   55               push ebp  ; jichi: hook here
  // 00258021   8bec             mov ebp,esp
  // 00258023   8b45 08          mov eax,dword ptr ss:[ebp+0x8] ; jichi: move arg1 to eax
  // 00258029   85c0             test eax,eax   ; check if text is null
  // 0025802b   0f84 d8000000    je .00258109
  // 00258031   837d 10 00       cmp dword ptr ss:[ebp+0x10],0x0 ; jichi: compare 0 with arg3, which is size+1
  // 00258035   0f84 ce000000    je .00258109
  // 0025803b   8b10             mov edx,dword ptr ds:[eax] ; move text address to edx
  DWORD arg1 = argof(1, esp_base), // mov eax,dword ptr ss:[ebp+0x8]
        arg3 = argof(3, esp_base); // size - 1
  if (arg1 && arg3)
    if (DWORD text = *(DWORD *)arg1)
      if (!(text > lasttext && text < lasttext + VNR_TEXT_CAPACITY)) { // text is not a subtext of lastText
        *data = lasttext = text; // mov edx,dword ptr ds:[eax]
        //*len = arg3 - 1; // the last char is the '\0', so -1, but this value is not reliable
        *len = ::strlen((LPCSTR)text);
        // Registers are not used as split as all of them are floating at runtime
        //*split = argof(4, esp_base); // arg4, always -8, this will merge all threads and result in repetition
        *split = argof(7, esp_base); // reduce repetition, but still have sub-text repeat
      }
}
bool InsertExpHook()
{
  const BYTE bytes[] = {
    0x55,                   // 00258020   55               push ebp  ; jichi: hook here, function starts, text in [arg1], size+1 in arg3
    0x8b,0xec,              // 00258021   8bec             mov ebp,esp
    0x8b,0x45, 0x08,        // 00258023   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
    0x83,0xec, 0x08,        // 00258026   83ec 08          sub esp,0x8
    0x85,0xc0,              // 00258029   85c0             test eax,eax
    0x0f,0x84, XX4,         // 0025802b   0f84 d8000000    je .00258109
    0x83,0x7d, 0x10, 0x00,  // 00258031   837d 10 00       cmp dword ptr ss:[ebp+0x10],0x0
    0x0f,0x84, XX4,         // 00258035   0f84 ce000000    je .00258109
    0x8b,0x10,              // 0025803b   8b10             mov edx,dword ptr ds:[eax] ; jichi: edx is the text
    0x8b,0x45, 0x0c,        // 0025803d   8b45 0c          mov eax,dword ptr ss:[ebp+0xc]
    0x53,                   // 00258040   53               push ebx
    0x56,                   // 00258041   56               push esi
    0xc7,0x45, 0xf8, 0x00,0x00,0x00,0x00,   // 00258042   c745 f8 00000000 mov dword ptr ss:[ebp-0x8],0x0
    0x89,0x45, 0xfc,        // 00258049   8945 fc          mov dword ptr ss:[ebp-0x4],eax
    0x57,                   // 0025804c   57               push edi
    0x8d,0x49, 0x00,        // 0025804d   8d49 00          lea ecx,dword ptr ds:[ecx]
    0x8a,0x0a               // 00258050   8a0a             mov cl,byte ptr ds:[edx]  ; jichi: text accessed in edx
  };
  enum { hook_offset = 0 };
  ULONG range = min(module_limit_ - module_base_, MAX_REL_ADDR);
  ULONG addr = MemDbg::matchBytes(bytes, sizeof(bytes), module_base_, module_base_ + range);
  //ITH_GROWL_DWORD(addr);
  if (!addr) {
    ConsoleOutput("vnreng:EXP: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.type = NO_CONTEXT|USING_STRING; // NO_CONTEXT to get rid of floating address
  hp.text_fun = SpecialHookExp;
  ConsoleOutput("vnreng: INSERT EXP");
  NewHook(hp, L"EXP");

  ConsoleOutput("vnreng:EXP: disable GDI hooks");
  DisableGDIHooks();
  return true;
}

/** 10/20/2014 jichi: HorkEye, http://horkeye.com
 *  Sample game: [150226] 結城友奈は勇者である 体験版
 *
 *  No GDI functions are used by this game.
 *
 *  Debug method:
 *  There are two matched texts.
 *  The one having fixed address is used to insert hw breakpoints.
 *
 *  I found are two functions addressing the address, both of which seems to be good.
 *  The first one is used:
 *
 *  013cda60   8d4c24 1c        lea ecx,dword ptr ss:[esp+0x1c]
 *  013cda64   51               push ecx
 *  013cda65   68 48a8c201      push .01c2a848                                     ; ascii "if"
 *  013cda6a   e8 d1291600      call .01530440
 *  013cda6f   83c4 0c          add esp,0xc
 *  013cda72   6a 01            push 0x1
 *  013cda74   83ec 1c          sub esp,0x1c
 *  013cda77   8bcc             mov ecx,esp
 *  013cda79   896424 30        mov dword ptr ss:[esp+0x30],esp
 *  013cda7d   6a 10            push 0x10
 *  013cda7f   c741 14 0f000000 mov dword ptr ds:[ecx+0x14],0xf
 *  013cda86   c741 10 00000000 mov dword ptr ds:[ecx+0x10],0x0
 *  013cda8d   68 80125601      push .01561280
 *  013cda92   c601 00          mov byte ptr ds:[ecx],0x0
 *  013cda95   e8 5681ffff      call .013c5bf0
 *  013cda9a   e8 717a0900      call .01465510
 *  013cda9f   83c4 20          add esp,0x20
 *  013cdaa2   b8 01000000      mov eax,0x1
 *  013cdaa7   8b8c24 b8000000  mov ecx,dword ptr ss:[esp+0xb8]
 *  013cdaae   5f               pop edi
 *  013cdaaf   5e               pop esi
 *  013cdab0   5d               pop ebp
 *  013cdab1   5b               pop ebx
 *  013cdab2   33cc             xor ecx,esp
 *  013cdab4   e8 c7361600      call .01531180
 *  013cdab9   81c4 ac000000    add esp,0xac
 *  013cdabf   c3               retn
 *  013cdac0   83ec 40          sub esp,0x40
 *  013cdac3   a1 24805d01      mov eax,dword ptr ds:[0x15d8024]
 *  013cdac8   8b15 c4709901    mov edx,dword ptr ds:[0x19970c4]
 *  013cdace   8d0c00           lea ecx,dword ptr ds:[eax+eax]
 *  013cdad1   a1 9c506b01      mov eax,dword ptr ds:[0x16b509c]
 *  013cdad6   0305 18805d01    add eax,dword ptr ds:[0x15d8018]
 *  013cdadc   53               push ebx
 *  013cdadd   8b5c24 48        mov ebx,dword ptr ss:[esp+0x48]
 *  013cdae1   55               push ebp
 *  013cdae2   8b6c24 50        mov ebp,dword ptr ss:[esp+0x50]
 *  013cdae6   894c24 34        mov dword ptr ss:[esp+0x34],ecx
 *  013cdaea   8b0d 20805d01    mov ecx,dword ptr ds:[0x15d8020]
 *  013cdaf0   894424 18        mov dword ptr ss:[esp+0x18],eax
 *  013cdaf4   a1 1c805d01      mov eax,dword ptr ds:[0x15d801c]
 *  013cdaf9   03c8             add ecx,eax
 *  013cdafb   56               push esi
 *  013cdafc   33f6             xor esi,esi
 *  013cdafe   d1f8             sar eax,1
 *  013cdb00   45               inc ebp
 *  013cdb01   896c24 24        mov dword ptr ss:[esp+0x24],ebp
 *  013cdb05   897424 0c        mov dword ptr ss:[esp+0xc],esi
 *  013cdb09   894c24 18        mov dword ptr ss:[esp+0x18],ecx
 *  013cdb0d   8a0c1a           mov cl,byte ptr ds:[edx+ebx]        jichi: here
 *  013cdb10   894424 30        mov dword ptr ss:[esp+0x30],eax
 *  013cdb14   8a441a 01        mov al,byte ptr ds:[edx+ebx+0x1]
 *  013cdb18   57               push edi
 *  013cdb19   897424 14        mov dword ptr ss:[esp+0x14],esi
 *  013cdb1d   3935 c8709901    cmp dword ptr ds:[0x19970c8],esi
 *
 *  The hooked place is only accessed once.
 *  013cdb0d   8a0c1a           mov cl,byte ptr ds:[edx+ebx]        jichi: here
 *  ebx is the text to be base address.
 *  edx is the offset to skip character name.
 *
 *  023B66A0  81 79 89 C4 EA A3 2C 53 30 30 35 5F 42 5F 30 30  【夏凜,S005_B_00
 *  023B66B0  30 32 81 7A 81 75 83 6F 81 5B 83 65 83 62 83 4E  02】「バーテック
 *  023B66C0  83 58 82 CD 82 B1 82 C1 82 BF 82 CC 93 73 8D 87  スはこっちの都合
 *  023B66D0  82 C8 82 C7 82 A8 8D 5C 82 A2 82 C8 82 B5 81 63  などお構いなし…
 *
 *  There are garbage in character name.
 *
 *  1/15/2015
 *  Alternative hook that might not need a text filter:
 *  http://www.hongfire.com/forum/showthread.php/36807-AGTH-text-extraction-tool-for-games-translation/page753
 *  /HA-4@552B5:姉小路直子と銀色の死神.exe
 *  If this hook no longer works, try that one instead.
 */
// Skip text between "," and "】", and remove [n]
// ex:【夏凜,S005_B_0002】「バーテック
static bool HorkEyeFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  size_t len = *size;
  char *str = reinterpret_cast<char *>(data),
       *start,
       *stop;

  // Remove text between , and ]
  if ((start = (char *)::memchr(str, ',', len)) &&
      (stop = cpp_strnstr(start, "\x81\x7a", len - (start - str))) &&
      (len -= stop - start)) // = u'】'.encode('sjis')
    ::memmove(start, stop, len - (start - str));

  // Remove [n]
  enum { skip_len = 3 }; // = length of "[n]"
  while (len >= skip_len &&
         (start = cpp_strnstr(str, "[n]", len)) &&
         (len -= skip_len))
    ::memmove(start, start + skip_len, len - (start - str));

  *size = len;
  return true;
}
bool InsertHorkEyeHook()
{
  const BYTE bytes[] = {
    0x89,0x6c,0x24, 0x24,   // 013cdb01   896c24 24        mov dword ptr ss:[esp+0x24],ebp
    0x89,0x74,0x24, 0x0c,   // 013cdb05   897424 0c        mov dword ptr ss:[esp+0xc],esi
    0x89,0x4c,0x24, 0x18,   // 013cdb09   894c24 18        mov dword ptr ss:[esp+0x18],ecx
    0x8a,0x0c,0x1a          // 013cdb0d   8a0c1a           mov cl,byte ptr ds:[edx+ebx]        jichi: here
  };
  enum { hook_offset = sizeof(bytes) - 3 }; // 8a0c1a
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:HorkEye: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = pusha_ebx_off -4;
  hp.type = USING_STRING|NO_CONTEXT|FIXING_SPLIT; // floating address
  hp.filter_fun = HorkEyeFilter;
  ConsoleOutput("vnreng: INSERT HorkEye");
  NewHook(hp, L"HorkEye");
  return true;
}

/** jichi 12/2/2014 5pb
 *
 *  Sample game: [140924] CROSS†CHANNEL 〜FINAL COMPLETE〜
 *  See: http://sakuradite.com/topic/528
 *
 *  Debugging method: insert breakpoint.
 *  The first matched function cannot extract prelude text.
 *  The second matched function can extract anything but contains garbage.
 *
 *  Function for scenario:
 *  0016d90e   cc               int3
 *  0016d90f   cc               int3
 *  0016d910   8b15 782b6e06    mov edx,dword ptr ds:[0x66e2b78]         ; .00b43bfe
 *  0016d916   8a0a             mov cl,byte ptr ds:[edx]	; jichi: hook here
 *  0016d918   33c0             xor eax,eax
 *  0016d91a   84c9             test cl,cl
 *  0016d91c   74 41            je short .0016d95f
 *  0016d91e   8bff             mov edi,edi
 *  0016d920   80f9 25          cmp cl,0x25
 *  0016d923   75 11            jnz short .0016d936
 *  0016d925   8a4a 01          mov cl,byte ptr ds:[edx+0x1]
 *  0016d928   42               inc edx
 *  0016d929   80f9 4e          cmp cl,0x4e
 *  0016d92c   74 05            je short .0016d933
 *  0016d92e   80f9 6e          cmp cl,0x6e
 *  0016d931   75 26            jnz short .0016d959
 *  0016d933   42               inc edx
 *  0016d934   eb 23            jmp short .0016d959
 *  0016d936   80f9 81          cmp cl,0x81
 *  0016d939   72 05            jb short .0016d940
 *  0016d93b   80f9 9f          cmp cl,0x9f
 *  0016d93e   76 0a            jbe short .0016d94a
 *  0016d940   80f9 e0          cmp cl,0xe0
 *  0016d943   72 0c            jb short .0016d951
 *  0016d945   80f9 fc          cmp cl,0xfc
 *  0016d948   77 07            ja short .0016d951
 *  0016d94a   b9 02000000      mov ecx,0x2
 *  0016d94f   eb 05            jmp short .0016d956
 *  0016d951   b9 01000000      mov ecx,0x1
 *  0016d956   40               inc eax
 *  0016d957   03d1             add edx,ecx
 *  0016d959   8a0a             mov cl,byte ptr ds:[edx]
 *  0016d95b   84c9             test cl,cl
 *  0016d95d  ^75 c1            jnz short .0016d920
 *  0016d95f   c3               retn
 *
 *  Function for everything:
 *  001e9a76   8bff             mov edi,edi
 *  001e9a78   55               push ebp
 *  001e9a79   8bec             mov ebp,esp
 *  001e9a7b   51               push ecx
 *  001e9a7c   8365 fc 00       and dword ptr ss:[ebp-0x4],0x0
 *  001e9a80   53               push ebx
 *  001e9a81   8b5d 10          mov ebx,dword ptr ss:[ebp+0x10]
 *  001e9a84   85db             test ebx,ebx
 *  001e9a86   75 07            jnz short .001e9a8f
 *  001e9a88   33c0             xor eax,eax
 *  001e9a8a   e9 9a000000      jmp .001e9b29
 *  001e9a8f   56               push esi
 *  001e9a90   83fb 04          cmp ebx,0x4
 *  001e9a93   72 75            jb short .001e9b0a
 *  001e9a95   8d73 fc          lea esi,dword ptr ds:[ebx-0x4]
 *  001e9a98   85f6             test esi,esi
 *  001e9a9a   74 6e            je short .001e9b0a
 *  001e9a9c   8b4d 0c          mov ecx,dword ptr ss:[ebp+0xc]
 *  001e9a9f   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  001e9aa2   8a10             mov dl,byte ptr ds:[eax]
 *  001e9aa4   83c0 04          add eax,0x4
 *  001e9aa7   83c1 04          add ecx,0x4
 *  001e9aaa   84d2             test dl,dl
 *  001e9aac   74 52            je short .001e9b00
 *  001e9aae   3a51 fc          cmp dl,byte ptr ds:[ecx-0x4]
 *  001e9ab1   75 4d            jnz short .001e9b00
 *  001e9ab3   8a50 fd          mov dl,byte ptr ds:[eax-0x3]
 *  001e9ab6   84d2             test dl,dl
 *  001e9ab8   74 3c            je short .001e9af6
 *  001e9aba   3a51 fd          cmp dl,byte ptr ds:[ecx-0x3]
 *  001e9abd   75 37            jnz short .001e9af6
 *  001e9abf   8a50 fe          mov dl,byte ptr ds:[eax-0x2]
 *  001e9ac2   84d2             test dl,dl
 *  001e9ac4   74 26            je short .001e9aec
 *  001e9ac6   3a51 fe          cmp dl,byte ptr ds:[ecx-0x2]
 *  001e9ac9   75 21            jnz short .001e9aec
 *  001e9acb   8a50 ff          mov dl,byte ptr ds:[eax-0x1]
 *  001e9ace   84d2             test dl,dl
 *  001e9ad0   74 10            je short .001e9ae2
 *  001e9ad2   3a51 ff          cmp dl,byte ptr ds:[ecx-0x1]
 *  001e9ad5   75 0b            jnz short .001e9ae2
 *  001e9ad7   8345 fc 04       add dword ptr ss:[ebp-0x4],0x4
 *  001e9adb   3975 fc          cmp dword ptr ss:[ebp-0x4],esi
 *  001e9ade  ^72 c2            jb short .001e9aa2
 *  001e9ae0   eb 2e            jmp short .001e9b10
 *  001e9ae2   0fb640 ff        movzx eax,byte ptr ds:[eax-0x1]
 *  001e9ae6   0fb649 ff        movzx ecx,byte ptr ds:[ecx-0x1]
 *  001e9aea   eb 46            jmp short .001e9b32
 *  001e9aec   0fb640 fe        movzx eax,byte ptr ds:[eax-0x2]
 *  001e9af0   0fb649 fe        movzx ecx,byte ptr ds:[ecx-0x2]
 *  001e9af4   eb 3c            jmp short .001e9b32
 *  001e9af6   0fb640 fd        movzx eax,byte ptr ds:[eax-0x3]
 *  001e9afa   0fb649 fd        movzx ecx,byte ptr ds:[ecx-0x3]
 *  001e9afe   eb 32            jmp short .001e9b32
 *  001e9b00   0fb640 fc        movzx eax,byte ptr ds:[eax-0x4]
 *  001e9b04   0fb649 fc        movzx ecx,byte ptr ds:[ecx-0x4]
 *  001e9b08   eb 28            jmp short .001e9b32
 *  001e9b0a   8b4d 0c          mov ecx,dword ptr ss:[ebp+0xc]
 *  001e9b0d   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  001e9b10   8b75 fc          mov esi,dword ptr ss:[ebp-0x4]
 *  001e9b13   eb 0d            jmp short .001e9b22
 *  001e9b15   8a10             mov dl,byte ptr ds:[eax]    ; jichi: here, word by word
 *  001e9b17   84d2             test dl,dl
 *  001e9b19   74 11            je short .001e9b2c
 *  001e9b1b   3a11             cmp dl,byte ptr ds:[ecx]
 *  001e9b1d   75 0d            jnz short .001e9b2c
 *  001e9b1f   40               inc eax
 *  001e9b20   46               inc esi
 *  001e9b21   41               inc ecx
 *  001e9b22   3bf3             cmp esi,ebx
 *  001e9b24  ^72 ef            jb short .001e9b15
 *  001e9b26   33c0             xor eax,eax
 *  001e9b28   5e               pop esi
 *  001e9b29   5b               pop ebx
 *  001e9b2a   c9               leave
 *  001e9b2b   c3               retn
 */
namespace { // unnamed

// Characters to ignore: [%0-9A-Z]
bool Insert5pbHook1()
{
  const BYTE bytes[] = {
    0xcc,           // 0016d90e   cc               int3
    0xcc,           // 0016d90f   cc               int3
    0x8b,0x15, XX4, // 0016d910   8b15 782b6e06    mov edx,dword ptr ds:[0x66e2b78]         ; .00b43bfe
    0x8a,0x0a,      // 0016d916   8a0a             mov cl,byte ptr ds:[edx]	; jichi: hook here
    0x33,0xc0,      // 0016d918   33c0             xor eax,eax
    0x84,0xc9       // 0016d91a   84c9             test cl,cl
  };
  enum { hook_offset = 0x0016d916 - 0x0016d90e };

  ULONG addr = MemDbg::matchBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  //ITH_GROWL_DWORD3(addr+hook_offset, module_base_,module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:5pb1: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = pusha_edx_off - 4;
  hp.type = USING_STRING;
  ConsoleOutput("vnreng: INSERT 5pb1");
  NewHook(hp, L"5pb1");

  // GDI functions are not used by 5pb games anyway.
  //ConsoleOutput("vnreng:5pb: disable GDI hooks");
  //DisableGDIHooks();
  return true;
}

// Characters to ignore: [%@A-z]
inline bool _5pb2garbage_ch(char c)
{ return c == '%' || c == '@' || c >= 'A' && c <= 'z'; }

// 001e9b15   8a10             mov dl,byte ptr ds:[eax]    ; jichi: here, word by word
void SpecialHook5pb2(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  static DWORD lasttext;
  DWORD text = regof(eax, esp_base);
  if (lasttext == text)
    return;
  BYTE c = *(BYTE *)text;
  if (!c)
    return;
  BYTE size = ::LeadByteTable[c]; // 1, 2, or 3
  if (size == 1 && _5pb2garbage_ch(*(LPCSTR)text))
    return;
  lasttext = text;
  *data = text;
  *len = size;
}

bool Insert5pbHook2()
{
  const BYTE bytes[] = {
    0x8a,0x10, // 001e9b15   8a10             mov dl,byte ptr ds:[eax]    ; jichi: here, word by word
    0x84,0xd2, // 001e9b17   84d2             test dl,dl
    0x74,0x11  // 001e9b19   74 11            je short .001e9b2c
  };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  //ITH_GROWL_DWORD3(addr, module_base_,module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:5pb2: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.type = USING_STRING;
  hp.text_fun = SpecialHook5pb2;
  //hp.off = pusha_eax_off - 4;
  //hp.length_offset = 1;
  ConsoleOutput("vnreng: INSERT 5pb2");
  NewHook(hp, L"5pb2");

  // GDI functions are not used by 5pb games anyway.
  //ConsoleOutput("vnreng:5pb: disable GDI hooks");
  //DisableGDIHooks();
  return true;
}

/** jichi 2/2/2015: New 5pb hook
 *  Sample game: Hyperdimension.Neptunia.ReBirth1
 *
 *  Debugging method: hardware breakpoint and find function in msvc110
 *  Then, backtrack the function stack to find proper function.
 *
 *  Hooked function: 558BEC56FF750C8BF1FF75088D460850
 *
 *  0025A12E   CC               INT3
 *  0025A12F   CC               INT3
 *  0025A130   55               PUSH EBP
 *  0025A131   8BEC             MOV EBP,ESP
 *  0025A133   56               PUSH ESI
 *  0025A134   FF75 0C          PUSH DWORD PTR SS:[EBP+0xC]
 *  0025A137   8BF1             MOV ESI,ECX
 *  0025A139   FF75 08          PUSH DWORD PTR SS:[EBP+0x8]
 *  0025A13C   8D46 08          LEA EAX,DWORD PTR DS:[ESI+0x8]
 *  0025A13F   50               PUSH EAX
 *  0025A140   E8 DB100100      CALL .0026B220
 *  0025A145   8B8E 988D0000    MOV ECX,DWORD PTR DS:[ESI+0x8D98]
 *  0025A14B   8988 80020000    MOV DWORD PTR DS:[EAX+0x280],ECX
 *  0025A151   8B8E A08D0000    MOV ECX,DWORD PTR DS:[ESI+0x8DA0]
 *  0025A157   8988 88020000    MOV DWORD PTR DS:[EAX+0x288],ECX
 *  0025A15D   8B8E A88D0000    MOV ECX,DWORD PTR DS:[ESI+0x8DA8]
 *  0025A163   8988 90020000    MOV DWORD PTR DS:[EAX+0x290],ECX
 *  0025A169   8B8E B08D0000    MOV ECX,DWORD PTR DS:[ESI+0x8DB0]
 *  0025A16F   8988 98020000    MOV DWORD PTR DS:[EAX+0x298],ECX
 *  0025A175   83C4 0C          ADD ESP,0xC
 *  0025A178   8D8E 188B0000    LEA ECX,DWORD PTR DS:[ESI+0x8B18]
 *  0025A17E   E8 DDD8FEFF      CALL .00247A60
 *  0025A183   5E               POP ESI
 *  0025A184   5D               POP EBP
 *  0025A185   C2 0800          RETN 0x8
 *  0025A188   CC               INT3
 *  0025A189   CC               INT3
 *
 *  Runtime stack, text in arg1, and name in arg2:
 *
 *  0015F93C   00252330  RETURN to .00252330 from .0025A130
 *  0015F940   181D0D4C  ASCII "That's my line! I won't let any of you
 *  take the title of True Goddess!"
 *  0015F944   0B8B4D20  ASCII "  White Heart  "
 *  0015F948   0B8B5528
 *  0015F94C   0B8B5524
 *  0015F950  /0015F980
 *  0015F954  |0026000F  RETURN to .0026000F from .002521D0
 *
 *
 *  Another candidate funciton for backup usage.
 *  Previous text in arg1.
 *  Current text in arg2.
 *  Current name in arg3.
 *
 *  0026B21C   CC               INT3
 *  0026B21D   CC               INT3
 *  0026B21E   CC               INT3
 *  0026B21F   CC               INT3
 *  0026B220   55               PUSH EBP
 *  0026B221   8BEC             MOV EBP,ESP
 *  0026B223   81EC A0020000    SUB ESP,0x2A0
 *  0026B229   BA A0020000      MOV EDX,0x2A0
 *  0026B22E   53               PUSH EBX
 *  0026B22F   8B5D 08          MOV EBX,DWORD PTR SS:[EBP+0x8]
 *  0026B232   56               PUSH ESI
 *  0026B233   57               PUSH EDI
 *  0026B234   8D041A           LEA EAX,DWORD PTR DS:[EDX+EBX]
 *  0026B237   B9 A8000000      MOV ECX,0xA8
 *  0026B23C   8BF3             MOV ESI,EBX
 *  0026B23E   8DBD 60FDFFFF    LEA EDI,DWORD PTR SS:[EBP-0x2A0]
 *  0026B244   F3:A5            REP MOVS DWORD PTR ES:[EDI],DWORD PTR DS>
 *  0026B246   B9 A8000000      MOV ECX,0xA8
 *  0026B24B   8BF0             MOV ESI,EAX
 *  0026B24D   8BFB             MOV EDI,EBX
 *  0026B24F   F3:A5            REP MOVS DWORD PTR ES:[EDI],DWORD PTR DS>
 *  0026B251   81C2 A0020000    ADD EDX,0x2A0
 *  0026B257   B9 A8000000      MOV ECX,0xA8
 *  0026B25C   8DB5 60FDFFFF    LEA ESI,DWORD PTR SS:[EBP-0x2A0]
 *  0026B262   8BF8             MOV EDI,EAX
 *  0026B264   F3:A5            REP MOVS DWORD PTR ES:[EDI],DWORD PTR DS>
 *  0026B266   81FA 40830000    CMP EDX,0x8340
 *  0026B26C  ^7C C6            JL SHORT .0026B234
 *  0026B26E   8BCB             MOV ECX,EBX
 *  0026B270   E8 EBC7FDFF      CALL .00247A60
 *  0026B275   FF75 0C          PUSH DWORD PTR SS:[EBP+0xC]
 *  0026B278   8B35 D8525000    MOV ESI,DWORD PTR DS:[0x5052D8]          ; msvcr110.sprintf
 *  0026B27E   68 805C5000      PUSH .00505C80                           ; ASCII "%s"
 *  0026B283   53               PUSH EBX
 *  0026B284   FFD6             CALL ESI
 *  0026B286   FF75 10          PUSH DWORD PTR SS:[EBP+0x10]
 *  0026B289   8D83 00020000    LEA EAX,DWORD PTR DS:[EBX+0x200]
 *  0026B28F   68 805C5000      PUSH .00505C80                           ; ASCII "%s"
 *  0026B294   50               PUSH EAX
 *  0026B295   FFD6             CALL ESI
 *  0026B297   83C4 18          ADD ESP,0x18
 *  0026B29A   8BC3             MOV EAX,EBX
 *  0026B29C   5F               POP EDI
 *  0026B29D   5E               POP ESI
 *  0026B29E   5B               POP EBX
 *  0026B29F   8BE5             MOV ESP,EBP
 *  0026B2A1   5D               POP EBP
 *  0026B2A2   C3               RETN
 *  0026B2A3   CC               INT3
 *  0026B2A4   CC               INT3
 *  0026B2A5   CC               INT3
 *  0026B2A6   CC               INT3
 */
void SpecialHook5pb3(DWORD esp_base, HookParam *, BYTE index, DWORD *data, DWORD *split, DWORD *len)
{
  // Text in arg1, name in arg2
  if (LPCSTR text = (LPCSTR)argof(index+1, esp_base))
    if (*text) {
      if (index)  // trim spaces in character name
        while (*text == ' ') text++;
      size_t sz = ::strlen(text);
      if (index)
        while (sz && text[sz-1] == ' ') sz--;
      *data = (DWORD)text;
      *len = sz;
      *split = FIXED_SPLIT_VALUE << index;
    }
}
bool Insert5pbHook3()
{
  const BYTE bytes[] = { // function starts
    0x55,            // 0025A130   55               PUSH EBP
    0x8b,0xec,       // 0025A131   8BEC             MOV EBP,ESP
    0x56,            // 0025A133   56               PUSH ESI
    0xff,0x75, 0x0c, // 0025A134   FF75 0C          PUSH DWORD PTR SS:[EBP+0xC]
    0x8b,0xf1,       // 0025A137   8BF1             MOV ESI,ECX
    0xff,0x75, 0x08, // 0025A139   FF75 08          PUSH DWORD PTR SS:[EBP+0x8]
    0x8d,0x46, 0x08, // 0025A13C   8D46 08          LEA EAX,DWORD PTR DS:[ESI+0x8]
    0x50,            // 0025A13F   50               PUSH EAX
    0xe8             // 0025A140   E8 DB100100      CALL .0026B220
  };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  //ITH_GROWL_DWORD3(addr, module_base_,module_limit_);
  if (!addr) {
    ConsoleOutput("vnreng:5pb2: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.type = USING_STRING|NO_CONTEXT;
  hp.text_fun = SpecialHook5pb3;
  hp.extra_text_count = 1; // extract character name in arg1
  hp.filter_fun = NewLineCharToSpaceFilter; // replace '\n' by ' '
  ConsoleOutput("vnreng: INSERT 5pb3");
  NewHook(hp, L"5pb3");
  // GDI functions are not used by 5pb games anyway.
  //ConsoleOutput("vnreng:5pb: disable GDI hooks");
  //DisableGDIHooks();
  return true;
}

} // unnamed namespace

bool Insert5pbHook()
{
  bool ok = Insert5pbHook1();
  ok = Insert5pbHook2() || ok;
  ok = Insert5pbHook3() || ok;
  return ok;
}

/** 12/23/2014 jichi: Mink games (not sure the engine name)
 *  Sample game:
 *  - [130111] [Mink EGO] お兄ちゃんにはぜったい言えないたいせつなこと。 -- /HB-4*0:64@45164A
 *  - [141219] [Mink] しすたー・すきーむ3
 *
 *  Observations from sisters3:
 *  - GetGlyphOutlineA can get text, but it is cached.
 *  - It's caller's first argument is the correct text, but I failed to find where it is called
 *  - Debugging text in memory caused looping
 *
 *  /HB-4*0:64@45164A
 *  - addr: 0x45164a
 *  - length_offset: 1
 *  - split: 0x64
 *  - off: 0xfffffff8 = -8
 *  - type: 0x18
 *
 *  Observations from Onechan:
 *  - There are lots of threads
 *  - The one with -1 split value is correct, but not sure for all games
 *  - The result texts still contain garbage, but can be split using return values.
 *
 *  00451611   e9 ee000000      jmp .00451704
 *  00451616   8b45 0c          mov eax,dword ptr ss:[ebp+0xc]
 *  00451619   3bc3             cmp eax,ebx
 *  0045161b   75 2b            jnz short .00451648
 *  0045161d   e8 a9340000      call .00454acb
 *  00451622   53               push ebx
 *  00451623   53               push ebx
 *  00451624   53               push ebx
 *  00451625   53               push ebx
 *  00451626   53               push ebx
 *  00451627   c700 16000000    mov dword ptr ds:[eax],0x16
 *  0045162d   e8 16340000      call .00454a48
 *  00451632   83c4 14          add esp,0x14
 *  00451635   385d f4          cmp byte ptr ss:[ebp-0xc],bl
 *  00451638   74 07            je short .00451641
 *  0045163a   8b45 f0          mov eax,dword ptr ss:[ebp-0x10]
 *  0045163d   8360 70 fd       and dword ptr ds:[eax+0x70],0xfffffffd
 *  00451641   33c0             xor eax,eax
 *  00451643   e9 bc000000      jmp .00451704
 *  00451648   3818             cmp byte ptr ds:[eax],bl
 *  0045164a   75 14            jnz short .00451660         ; jichi: hook here
 *  0045164c   385d f4          cmp byte ptr ss:[ebp-0xc],bl
 *  0045164f   74 07            je short .00451658
 *  00451651   8b45 f0          mov eax,dword ptr ss:[ebp-0x10]
 *  00451654   8360 70 fd       and dword ptr ds:[eax+0x70],0xfffffffd
 *  00451658   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
 *  0045165b   e9 a4000000      jmp .00451704
 *  00451660   56               push esi
 *  00451661   8b75 08          mov esi,dword ptr ss:[ebp+0x8]
 *  00451664   3bf3             cmp esi,ebx
 *  00451666   75 28            jnz short .00451690
 *  00451668   e8 5e340000      call .00454acb
 *  0045166d   53               push ebx
 *  0045166e   53               push ebx
 *  0045166f   53               push ebx
 *  00451670   53               push ebx
 *  00451671   53               push ebx
 *  00451672   c700 16000000    mov dword ptr ds:[eax],0x16
 *  00451678   e8 cb330000      call .00454a48
 *  0045167d   83c4 14          add esp,0x14
 *  00451680   385d f4          cmp byte ptr ss:[ebp-0xc],bl
 *  00451683   74 07            je short .0045168c
 *  00451685   8b45 f0          mov eax,dword ptr ss:[ebp-0x10]
 *  00451688   8360 70 fd       and dword ptr ds:[eax+0x70],0xfffffffd
 *  0045168c   33c0             xor eax,eax
 *  0045168e   eb 73            jmp short .00451703
 *  00451690   57               push edi
 *  00451691   50               push eax
 *  00451692   8bfe             mov edi,esi
 *  00451694   e8 a7600000      call .00457740
 *  00451699   8975 f8          mov dword ptr ss:[ebp-0x8],esi
 *  0045169c   2945 f8          sub dword ptr ss:[ebp-0x8],eax
 *  0045169f   56               push esi
 *  004516a0   e8 9b600000      call .00457740
 *  004516a5   0345 f8          add eax,dword ptr ss:[ebp-0x8]
 *  004516a8   59               pop ecx
 *  004516a9   59               pop ecx
 *  004516aa   381e             cmp byte ptr ds:[esi],bl
 *  004516ac   74 46            je short .004516f4
 *  004516ae   2b75 0c          sub esi,dword ptr ss:[ebp+0xc]
 *  004516b1   3bf8             cmp edi,eax
 *  004516b3   77 3f            ja short .004516f4
 *  004516b5   8a17             mov dl,byte ptr ds:[edi]
 *  004516b7   8b4d 0c          mov ecx,dword ptr ss:[ebp+0xc]
 *  004516ba   8855 ff          mov byte ptr ss:[ebp-0x1],dl
 *  004516bd   3ad3             cmp dl,bl
 *  004516bf   74 11            je short .004516d2
 *  004516c1   8a11             mov dl,byte ptr ds:[ecx]
 *  004516c3   3ad3             cmp dl,bl
 *  004516c5   74 40            je short .00451707
 *  004516c7   38140e           cmp byte ptr ds:[esi+ecx],dl
 *  004516ca   75 06            jnz short .004516d2
 *  004516cc   41               inc ecx
 *  004516cd   381c0e           cmp byte ptr ds:[esi+ecx],bl
 *  004516d0  ^75 ef            jnz short .004516c1
 *  004516d2   3819             cmp byte ptr ds:[ecx],bl
 *  004516d4   74 31            je short .00451707
 *  004516d6   0fb64d ff        movzx ecx,byte ptr ss:[ebp-0x1]
 *  004516da   8b55 ec          mov edx,dword ptr ss:[ebp-0x14]
 *  004516dd   8a4c11 1d        mov cl,byte ptr ds:[ecx+edx+0x1d]
 */

#if 0 // hook to the caller of dynamic GetGlyphOutlineA
/**
 *  @param  addr  function address
 *  @param  frame  real address of the function, supposed to be the same as addr
 *  @param  stack  address of current stack - 4
 *  @return  If suceess
 */
static bool InsertMinkDynamicHook(LPVOID fun, DWORD frame, DWORD stack)
{
  CC_UNUSED(frame);
  if (fun != ::GetGlyphOutlineA)
    return false;
  DWORD addr = *(DWORD *)(stack + 4);
  if (!addr) {
    ConsoleOutput("vnreng:Mink: missing function return addr, this should never happen");
    return true;
  }
  addr = MemDbg::findEnclosingAlignedFunction(addr, 0x200); // range is around 0x120
  if (!addr) {
    ConsoleOutput("vnreng:Mink: failed to caller address");
    return true;
  }

  HookParam hp = {};
  hp.addr = addr; // hook to the beginning of the caller function
  hp.off = 4 * 1; // text character is in arg1
  hp.length_offset = 1; // only 1 character
  hp.type = BIG_ENDIAN;
  NewHook(hp, L"Mink");

  ConsoleOutput("vnreng:Mink: disable GDI hooks");
  DisableGDIHooks();
  return true;
}
#endif // 0

static void SpecialHookMink(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  //DWORD addr = *(DWORD *)(esp_base + hp->off); // default value
  DWORD addr = regof(eax, esp_base);
  if (!IthGetMemoryRange((LPVOID)(addr), 0, 0))
    return;
  DWORD ch = *(DWORD *)addr;
  DWORD size = LeadByteTable[ch & 0xff]; // Slightly faster than IsDBCSLeadByte
  if (size == 1 && ::ispunct(ch & 0xff)) // skip ascii punctuations, since garbage is like ":text:"
    return;

  *len = size;
  *data = ch;

  // Issue: still have lots of garbage
  *split = *(DWORD *)(esp_base + 0x64);
  //*split = *(DWORD *)(esp_base + 0x48);
}

bool InsertMinkHook()
{
  const BYTE bytes[] = {
    0x38,0x18,              // 00451648   3818             cmp byte ptr ds:[eax],bl
    0x75, 0x14,             // 0045164a   75 14            jnz short .00451660         ; jichi: hook here
    0x38,0x5d, 0xf4,        // 0045164c   385d f4          cmp byte ptr ss:[ebp-0xc],bl
    0x74, 0x07,             // 0045164f   74 07            je short .00451658
    0x8b,0x45, 0xf0,        // 00451651   8b45 f0          mov eax,dword ptr ss:[ebp-0x10]
    0x83,0x60, 0x70, 0xfd,  // 00451654   8360 70 fd       and dword ptr ds:[eax+0x70],0xfffffffd
    0x8b,0x45, 0x08         // 00451658   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
  };
  enum { hook_offset = 2 };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  //ULONG addr = 0x45164a;
  //ULONG addr = 0x451648;
  //ULONG addr = 0x4521a8;
  //ITH_GROWL_DWORD(addr);
  if (!addr) {
    ConsoleOutput("vnreng:Mink: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = pusha_eax_off - 4; // -8
  hp.length_offset = 1;
  hp.split = 0x64;
  hp.type = USING_SPLIT|DATA_INDIRECT; // 0x18
  hp.text_fun = SpecialHookMink;
  ConsoleOutput("vnreng: INSERT Mink");
  NewHook(hp, L"Mink");

  //ConsoleOutput("vnreng:Mink: disable GDI hooks");
  //DisableGDIHooks();
  return true;
}

/** jichi 12/25/2014: Leaf/AQUAPLUS
 *  Sample game: [141224] [AQUAPLUS] WHITE ALBUM2 ミニアフターストーリー
 *  Debug method: hardware break found text
 *  The text address is fixed.
 *  There are three matched functions.
 *  It can find both character name and scenario.
 *
 *  The scenario text contains "\n".
 *
 *  Instructions:
 *
 *  00451650   5b               pop ebx
 *  00451651   5f               pop edi
 *  00451652   8bc6             mov eax,esi
 *  00451654   5e               pop esi
 *  00451655   c2 0400          retn 0x4
 *  00451658   8b90 c08c0000    mov edx,dword ptr ds:[eax+0x8cc0]
 *  0045165e   8b8497 14080000  mov eax,dword ptr ds:[edi+edx*4+0x814]
 *  00451665   8d58 01          lea ebx,dword ptr ds:[eax+0x1] ; jichi: hook here would crash
 *  00451668   8a10             mov dl,byte ptr ds:[eax]    ; jichi: text accessed here in eax
 *  0045166a   40               inc eax
 *  0045166b   84d2             test dl,dl
 *  0045166d  ^75 f9            jnz short .00451668
 *  0045166f   2bc3             sub eax,ebx     ; jichi: hook here, text in ebx-1
 *  00451671   8d58 01          lea ebx,dword ptr ds:[eax+0x1]
 *  00451674   53               push ebx
 *  00451675   6a 00            push 0x0
 *  00451677   53               push ebx
 *  00451678   6a 00            push 0x0
 *  0045167a   ff15 74104a00    call dword ptr ds:[0x4a1074]             ; kernel32.getprocessheap
 *  00451680   50               push eax
 *  00451681   ff15 b4104a00    call dword ptr ds:[0x4a10b4]             ; ntdll.rtlallocateheap
 *  00451687   50               push eax
 *  00451688   e8 233e0200      call .004754b0
 *
 *  EAX 00000038
 *  ECX 00000004 ; jichi: fixed
 *  EDX 00000000 ; jichi: fixed
 *  EBX 00321221
 *  ESP 0012FD98
 *  EBP 00000002
 *  ESI 0012FDC4
 *  EDI 079047E0
 *  EIP 00451671 .00451671
 */
static void SpecialHookLeaf(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD text = regof(ebx, esp_base) - 1; // = ebx -1
  *data = text;
  *len = ::strlen((LPCSTR)text);
  *split = FIXED_SPLIT_VALUE; // only caller's address use as split
}
// Remove both \n and \k
static bool LeafFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  LPSTR text = (LPSTR)data;
  if (::memchr(text, '\\', *size)) {
    StringFilter(text, reinterpret_cast<size_t *>(size), "\\n", 2);
    StringFilter(text, reinterpret_cast<size_t *>(size), "\\k", 2);
  }
  return true;
}
bool InsertLeafHook()
{
  const BYTE bytes[] = {
    0x8b,0x90, XX4,      // 00451658   8b90 c08c0000    mov edx,dword ptr ds:[eax+0x8cc0]
    0x8b,0x84,0x97, XX4, // 0045165e   8b8497 14080000  mov eax,dword ptr ds:[edi+edx*4+0x814]
    // The above is needed as there are other matches
    0x8d,0x58, 0x01,     // 00451665   8d58 01          lea ebx,dword ptr ds:[eax+0x1] ; jichi: hook here would crash because of jump
    0x8a,0x10,           // 00451668   8a10             mov dl,byte ptr ds:[eax]    ; jichi: text accessed here in eax
    0x40,                // 0045166a   40               inc eax
    0x84,0xd2,           // 0045166b   84d2             test dl,dl
    0x75, 0xf9,          // 0045166d  ^75 f9            jnz short .00451668
    0x2b,0xc3,           // 0045166f   2bc3             sub eax,ebx     ; jichi: hook here, text in ebx-1
    0x8d,0x58, 0x01      // 00451671   8d58 01           lea ebx,dword ptr ds:[eax+0x1]
    //0x53,               // 00451674   53               push ebx
    //0x6a, 0x00,         // 00451675   6a 00            push 0x0
    //0x53,               // 00451677   53               push ebx
    //0x6a, 0x00,         // 00451678   6a 00            push 0x0
    //0xff,0x15           // 0045167a   ff15 74104a00    call dword ptr ds:[0x4a1074]             ; kernel32.getprocessheap
  };
  ULONG addr = MemDbg::matchBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  enum { hook_offset = 0x0045166f - 0x00451658 };
  //ITH_GROWL_DWORD(addr);
  if (!addr) {
    ConsoleOutput("vnreng:Leaf: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr + hook_offset;
  //hp.off = pusha_eax_off - 4;
  hp.type = USING_STRING|USING_SPLIT;
  hp.text_fun = SpecialHookLeaf;
  //hp.filter_fun = NewLineStringFilter; // remove two characters of "\\n"
  hp.filter_fun = LeafFilter; // remove two characters
  ConsoleOutput("vnreng: INSERT Leaf");
  NewHook(hp, L"Leaf");

  //ConsoleOutput("vnreng:Leaf: disable GDI hooks");
  //DisableGDIHooks();
  return true;
}

/** jichi 12/27/2014 LunaSoft
 * Sample game: [141226] [LunaSoft] 悪堕ラビリンス -- /hsn8@46C5EF
 *
 * /hsn8@46C5EF
 * - addr: 0x46C5EF
 * - off: 8
 * - type: 1025 = 0x401
 *
 * - 0046c57e   cc               int3
 * - 0046c57f   cc               int3
 * - 0046c580   55               push ebp       ; jichi: text in arg1
 * - 0046c581   8bec             mov ebp,esp
 * - 0046c583   83ec 08          sub esp,0x8
 * - 0046c586   894d f8          mov dword ptr ss:[ebp-0x8],ecx
 * - 0046c589   8b4d f8          mov ecx,dword ptr ss:[ebp-0x8]
 * - 0046c58c   83c1 1c          add ecx,0x1c
 * - 0046c58f   e8 2cebf9ff      call .0040b0c0
 * - 0046c594   8b00             mov eax,dword ptr ds:[eax]
 * - 0046c596   8945 fc          mov dword ptr ss:[ebp-0x4],eax
 * - 0046c599   837d fc 00       cmp dword ptr ss:[ebp-0x4],0x0
 * - 0046c59d   75 21            jnz short .0046c5c0
 * - 0046c59f   8b4d f8          mov ecx,dword ptr ss:[ebp-0x8]
 * - 0046c5a2   83c1 28          add ecx,0x28
 * - 0046c5a5   e8 16ebf9ff      call .0040b0c0
 * - 0046c5aa   8b08             mov ecx,dword ptr ds:[eax]
 * - 0046c5ac   894d fc          mov dword ptr ss:[ebp-0x4],ecx
 * - 0046c5af   8b55 fc          mov edx,dword ptr ss:[ebp-0x4]
 * - 0046c5b2   52               push edx
 * - 0046c5b3   8b4d f8          mov ecx,dword ptr ss:[ebp-0x8]
 * - 0046c5b6   83c1 28          add ecx,0x28
 * - 0046c5b9   e8 82d9f9ff      call .00409f40
 * - 0046c5be   eb 0f            jmp short .0046c5cf
 * - 0046c5c0   8b45 fc          mov eax,dword ptr ss:[ebp-0x4]
 * - 0046c5c3   50               push eax
 * - 0046c5c4   8b4d f8          mov ecx,dword ptr ss:[ebp-0x8]
 * - 0046c5c7   83c1 1c          add ecx,0x1c
 * - 0046c5ca   e8 71d9f9ff      call .00409f40
 * - 0046c5cf   837d fc 00       cmp dword ptr ss:[ebp-0x4],0x0
 * - 0046c5d3   75 02            jnz short .0046c5d7
 * - 0046c5d5   eb 61            jmp short .0046c638
 * - 0046c5d7   8b4d fc          mov ecx,dword ptr ss:[ebp-0x4]
 * - 0046c5da   e8 b1cdf9ff      call .00409390
 * - 0046c5df   8b4d 08          mov ecx,dword ptr ss:[ebp+0x8]
 * - 0046c5e2   51               push ecx                   ; jichi: text in ecx
 * - 0046c5e3   68 38010000      push 0x138
 * - 0046c5e8   8b55 fc          mov edx,dword ptr ss:[ebp-0x4]
 * - 0046c5eb   83c2 08          add edx,0x8
 * - 0046c5ee   52               push edx
 * - 0046c5ef   ff15 88b24c00    call dword ptr ds:[0x4cb288]  ; msvcr90.strcpy_s, jichi: text accessed here in arg2
 * - 0046c5f5   83c4 0c          add esp,0xc
 * - 0046c5f8   8b45 0c          mov eax,dword ptr ss:[ebp+0xc]
 * - 0046c5fb   50               push eax
 * - 0046c5fc   6a 10            push 0x10
 */
// Remove: \n\s*
// This is dangerous since \n could appear within SJIS
//static bool LunaSoftFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
//{
//  size_t len = *size;
//  char *str = reinterpret_cast<char *>(data),
//       *cur;
//
//  while (len &&
//         (cur = ::memchr(str, '\n', len)) &&
//         --len) {
//    ::memmove(cur, cur + 1, len - (cur - str));
//    while (cur < str + len)
//      if (::isspace(*cur) && --len)
//        ::memmove(cur, cur + 1, len - (cur - str));
//      else if (len >= 2 && ::iswspace(*(LPCWSTR)cur) && (len-=2))
//        ::memmove(cur, cur + 2, len - (cur - str));
//      else
//        break;
//  }
//
//  *size = len;
//  return true;
//}
bool InsertLunaSoftHook()
{
  const BYTE bytes[] = {
    0xcc,            // 0046c57e   cc               int3
    0xcc,            // 0046c57f   cc               int3
    0x55,            // 0046c580   55               push ebp       ; jichi: text in arg1
    0x8b,0xec,       // 0046c581   8bec             mov ebp,esp
    0x83,0xec, 0x08, // 0046c583   83ec 08          sub esp,0x8
    0x89,0x4d, 0xf8, // 0046c586   894d f8          mov dword ptr ss:[ebp-0x8],ecx
    0x8b,0x4d, 0xf8, // 0046c589   8b4d f8          mov ecx,dword ptr ss:[ebp-0x8]
    0x83,0xc1, 0x1c, // 0046c58c   83c1 1c          add ecx,0x1c
    0xe8             // 0046c58f   e8 2cebf9ff      call .0040b0c0
  };
  enum { hook_offset = 2 };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  //ITH_GROWL(addr);
  if (!addr) {
    ConsoleOutput("vnreng:LunaSoft: pattern not found");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = 1 * 4; // arg1
  hp.type = USING_STRING;
  //hp.filter_fun = LunaSoftFilter; // remove \n
  ConsoleOutput("vnreng: INSERT LunaSoft");
  NewHook(hp, L"LunaSoft");

  // There are no GDI functions anyway
  //ConsoleOutput("vnreng:LunaSoft: disable GDI hooks");
  //DisableGDIHooks();
  return true;
}

/** jichi 2/6/2015 FocasLens (Touhou)
 *  Sample game: [141227] [FocasLens] 幻想人形演舞
 *
 *  Debugging method:
 *  1. Find first matched text, which has stable address
 *  2. Insert WRITE hw break point
 *  3. Find where the text is assigned
 *
 *  The game also invokes GDI functions (GetGlyphOutlineA), where the access is cached and looped.
 *
 *  Issues:
 *  - This hook cannot find name thread
 *  - Selected character name is hard-coded to the thread
 *
 *  001faaed   cc               int3
 *  001faaee   cc               int3
 *  001faaef   cc               int3
 *  001faaf0   55               push ebp
 *  001faaf1   8bec             mov ebp,esp
 *  001faaf3   51               push ecx
 *  001faaf4   53               push ebx
 *  001faaf5   56               push esi
 *  001faaf6   57               push edi
 *  001faaf7   8bf0             mov esi,eax
 *  001faaf9   e8 98281500      call .0034d396
 *  001faafe   50               push eax
 *  001faaff   a1 b08bb100      mov eax,dword ptr ds:[0xb18bb0]
 *  001fab04   03c6             add eax,esi
 *  001fab06   50               push eax
 *  001fab07   e8 9b241500      call .0034cfa7
 *  001fab0c   8b0d e88bb100    mov ecx,dword ptr ds:[0xb18be8]
 *  001fab12   8b3d b08bb100    mov edi,dword ptr ds:[0xb18bb0]
 *  001fab18   83c1 f7          add ecx,-0x9
 *  001fab1b   83c4 08          add esp,0x8
 *  001fab1e   8bd8             mov ebx,eax
 *  001fab20   390d ec8bb100    cmp dword ptr ds:[0xb18bec],ecx
 *  001fab26   7c 65            jl short .001fab8d
 *  001fab28   803c37 20        cmp byte ptr ds:[edi+esi],0x20
 *  001fab2c   74 41            je short .001fab6f
 *  001fab2e   803c37 81        cmp byte ptr ds:[edi+esi],0x81
 *  001fab32   75 4d            jnz short .001fab81
 *  001fab34   807c37 01 42     cmp byte ptr ds:[edi+esi+0x1],0x42
 *  001fab39   74 34            je short .001fab6f
 *  001fab3b   803c37 81        cmp byte ptr ds:[edi+esi],0x81
 *  001fab3f   75 40            jnz short .001fab81
 *  001fab41   807c37 01 41     cmp byte ptr ds:[edi+esi+0x1],0x41
 *  001fab46   74 27            je short .001fab6f
 *  001fab48   803c37 81        cmp byte ptr ds:[edi+esi],0x81
 *  001fab4c   75 33            jnz short .001fab81
 *  001fab4e   807c37 01 48     cmp byte ptr ds:[edi+esi+0x1],0x48
 *  001fab53   74 1a            je short .001fab6f
 *  001fab55   803c37 81        cmp byte ptr ds:[edi+esi],0x81
 *  001fab59   75 26            jnz short .001fab81
 *  001fab5b   807c37 01 49     cmp byte ptr ds:[edi+esi+0x1],0x49
 *  001fab60   74 0d            je short .001fab6f
 *  001fab62   803c37 81        cmp byte ptr ds:[edi+esi],0x81
 *  001fab66   75 19            jnz short .001fab81
 *  001fab68   807c37 01 40     cmp byte ptr ds:[edi+esi+0x1],0x40
 *  001fab6d   75 12            jnz short .001fab81
 *  001fab6f   803d c58bb100 00 cmp byte ptr ds:[0xb18bc5],0x0
 *  001fab76   75 09            jnz short .001fab81
 *  001fab78   c605 c58bb100 01 mov byte ptr ds:[0xb18bc5],0x1
 *  001fab7f   eb 0c            jmp short .001fab8d
 *  001fab81   e8 7a000000      call .001fac00
 *  001fab86   c605 c58bb100 00 mov byte ptr ds:[0xb18bc5],0x0
 *  001fab8d   8b0d e48bb100    mov ecx,dword ptr ds:[0xb18be4]
 *  001fab93   33c0             xor eax,eax
 *  001fab95   85db             test ebx,ebx
 *  001fab97   7e 2b            jle short .001fabc4
 *  001fab99   8d1437           lea edx,dword ptr ds:[edi+esi]
 *  001fab9c   8b35 ec8bb100    mov esi,dword ptr ds:[0xb18bec]
 *  001faba2   8955 fc          mov dword ptr ss:[ebp-0x4],edx
 *  001faba5   8bd1             mov edx,ecx
 *  001faba7   0faf15 e88bb100  imul edx,dword ptr ds:[0xb18be8]
 *  001fabae   0315 bc8bb100    add edx,dword ptr ds:[0xb18bbc]          ; .00b180f8
 *  001fabb4   03f2             add esi,edx
 *  001fabb6   8b55 fc          mov edx,dword ptr ss:[ebp-0x4]
 *  001fabb9   8a1402           mov dl,byte ptr ds:[edx+eax]
 *  001fabbc   881406           mov byte ptr ds:[esi+eax],dl    ; jichi: text is in dl in byte
 *  001fabbf   40               inc eax
 *  001fabc0   3bc3             cmp eax,ebx
 *  001fabc2  ^7c f2            jl short .001fabb6
 *  001fabc4   0faf0d e88bb100  imul ecx,dword ptr ds:[0xb18be8]
 *  001fabcb   030d bc8bb100    add ecx,dword ptr ds:[0xb18bbc]          ; .00b180f8
 *  001fabd1   a1 ec8bb100      mov eax,dword ptr ds:[0xb18bec]
 *  001fabd6   03fb             add edi,ebx
 *  001fabd8   893d b08bb100    mov dword ptr ds:[0xb18bb0],edi
 *  001fabde   5f               pop edi
 *  001fabdf   03c8             add ecx,eax
 *  001fabe1   03c3             add eax,ebx
 *  001fabe3   5e               pop esi
 *  001fabe4   c60419 00        mov byte ptr ds:[ecx+ebx],0x0
 *  001fabe8   a3 ec8bb100      mov dword ptr ds:[0xb18bec],eax
 *  001fabed   5b               pop ebx
 *  001fabee   8be5             mov esp,ebp
 *  001fabf0   5d               pop ebp
 *  001fabf1   c3               retn
 *  001fabf2   cc               int3
 *  001fabf3   cc               int3
 *  001fabf4   cc               int3
 *  001fabf5   cc               int3
 *  001fabf6   cc               int3
 *  001fabf7   cc               int3
 */
static void SpecialHookFocasLens(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD addr  = esp_base + pusha_edx_off - 4;
  if (*(char *)addr) {
    *data = addr;
    *len = 1;
    *split = FIXED_SPLIT_VALUE;
  }
}
bool InsertFocasLensHook()
{
  const BYTE bytes[] = {
    0x8a,0x14,0x02, // 001fabb9   8a1402           mov dl,byte ptr ds:[edx+eax]
    0x88,0x14,0x06, // 001fabbc   881406           mov byte ptr ds:[esi+eax],dl    ; jichi: text is in dl in byte
    0x40,           // 001fabbf   40               inc eax
    0x3b,0xc3       // 001fabc0   3bc3             cmp eax,ebx
  };
  enum { hook_offset = 0x001fabbc - 0x001fabb9 };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  //ITH_GROWL(addr);
  if (!addr) {
    ConsoleOutput("vnreng:FocasLens: pattern not found");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr + hook_offset;
  //hp.off = pusha_edx_off - 4;
  //hp.length_offset = 1; // Why this does not work?!
  //hp.split = pusha_eax_off - 4; // use eax as split
  hp.text_fun = SpecialHookFocasLens; // use special hook to force byte access
  hp.type = USING_STRING|USING_SPLIT|FIXING_SPLIT|NO_CONTEXT; // no context to get rid of relative function address
  ConsoleOutput("vnreng: INSERT FocasLens");
  NewHook(hp, L"FocasLens");

  // GDI functions are kept in case the font is not cached
  //DisableGDIHooks();
  return true;
}

/** jichi 2/6/2015 Syuntada
 *  Sample game: [140816] [平安亭] カノジョのお母さんは好きですか？ -- /HA-18@6944C:kanojo.exe
 *
 *  /HA-18@6944C:kanojo.exe
 *  - addr: 431180 = 0x6944c
 *  - module: 1301076281
 *  - off: 4294967268 = 0xffffffe4 = - 0x1c
 *  - length_offset: 1
 *  - type: 68 = 0x44
 *
 *  004692bd   cc               int3
 *  004692be   cc               int3
 *  004692bf   cc               int3
 *  004692c0   83ec 48          sub esp,0x48
 *  004692c3   53               push ebx
 *  004692c4   55               push ebp
 *  004692c5   56               push esi
 *  004692c6   8bf1             mov esi,ecx
 *  004692c8   8b86 d4000000    mov eax,dword ptr ds:[esi+0xd4]
 *  004692ce   0386 8c040000    add eax,dword ptr ds:[esi+0x48c]
 *  004692d4   8b8e c8010000    mov ecx,dword ptr ds:[esi+0x1c8]
 *  004692da   8b9e 90040000    mov ebx,dword ptr ds:[esi+0x490]
 *  004692e0   03c0             add eax,eax
 *  004692e2   03c0             add eax,eax
 *  004692e4   894424 24        mov dword ptr ss:[esp+0x24],eax
 *  004692e8   8b86 c4010000    mov eax,dword ptr ds:[esi+0x1c4]
 *  004692ee   8986 94040000    mov dword ptr ds:[esi+0x494],eax
 *  004692f4   8b4424 60        mov eax,dword ptr ss:[esp+0x60]
 *  004692f8   898e 98040000    mov dword ptr ds:[esi+0x498],ecx
 *  004692fe   0fb628           movzx ebp,byte ptr ds:[eax]
 *  00469301   0fb650 01        movzx edx,byte ptr ds:[eax+0x1]
 *  00469305   c1e5 08          shl ebp,0x8
 *  00469308   0bea             or ebp,edx
 *  0046930a   03db             add ebx,ebx
 *  0046930c   03db             add ebx,ebx
 *  0046930e   8d8d 617dffff    lea ecx,dword ptr ss:[ebp+0xffff7d61]
 *  00469314   57               push edi
 *  00469315   895c24 30        mov dword ptr ss:[esp+0x30],ebx
 *  00469319   c74424 38 100000>mov dword ptr ss:[esp+0x38],0x10
 *  00469321   896c24 34        mov dword ptr ss:[esp+0x34],ebp
 *  00469325   b8 02000000      mov eax,0x2
 *  0046932a   83f9 52          cmp ecx,0x52
 *  0046932d   77 02            ja short .00469331
 *  0046932f   33c0             xor eax,eax
 *  00469331   81fd 41810000    cmp ebp,0x8141
 *  00469337   7c 08            jl short .00469341
 *  00469339   81fd 9a820000    cmp ebp,0x829a
 *  0046933f   7e 0e            jle short .0046934f
 *  00469341   8d95 c07cffff    lea edx,dword ptr ss:[ebp+0xffff7cc0]
 *  00469347   81fa 4f040000    cmp edx,0x44f
 *  0046934d   77 09            ja short .00469358
 *  0046934f   bf 01000000      mov edi,0x1
 *  00469354   8bc7             mov eax,edi
 *  00469356   eb 05            jmp short .0046935d
 *  00469358   bf 01000000      mov edi,0x1
 *  0046935d   83e8 00          sub eax,0x0
 *  00469360   74 2a            je short .0046938c
 *  00469362   2bc7             sub eax,edi
 *  00469364   74 0c            je short .00469372
 *  00469366   2bc7             sub eax,edi
 *  00469368   75 3a            jnz short .004693a4
 *  0046936a   8b96 68010000    mov edx,dword ptr ds:[esi+0x168]
 *  00469370   eb 20            jmp short .00469392
 *  00469372   8b96 7c090000    mov edx,dword ptr ds:[esi+0x97c]
 *  00469378   8b86 64010000    mov eax,dword ptr ds:[esi+0x164]
 *  0046937e   8b52 28          mov edx,dword ptr ds:[edx+0x28]
 *  00469381   8d8e 7c090000    lea ecx,dword ptr ds:[esi+0x97c]
 *  00469387   50               push eax
 *  00469388   ffd2             call edx
 *  0046938a   eb 18            jmp short .004693a4
 *  0046938c   8b96 60010000    mov edx,dword ptr ds:[esi+0x160]
 *  00469392   8b86 7c090000    mov eax,dword ptr ds:[esi+0x97c]
 *  00469398   8b40 28          mov eax,dword ptr ds:[eax+0x28]
 *  0046939b   8d8e 7c090000    lea ecx,dword ptr ds:[esi+0x97c]
 *  004693a1   52               push edx
 *  004693a2   ffd0             call eax
 *  004693a4   39be d40f0000    cmp dword ptr ds:[esi+0xfd4],edi
 *  004693aa   75 45            jnz short .004693f1
 *  004693ac   8b8e 90040000    mov ecx,dword ptr ds:[esi+0x490]
 *  004693b2   b8 d0020000      mov eax,0x2d0
 *  004693b7   2bc1             sub eax,ecx
 *  004693b9   2b86 c8010000    sub eax,dword ptr ds:[esi+0x1c8]
 *  004693bf   68 000f0000      push 0xf00
 *  004693c4   8d0480           lea eax,dword ptr ds:[eax+eax*4]
 *  004693c7   c1e0 08          shl eax,0x8
 *  004693ca   0386 c4010000    add eax,dword ptr ds:[esi+0x1c4]
 *  004693d0   8d1440           lea edx,dword ptr ds:[eax+eax*2]
 *  004693d3   8b4424 60        mov eax,dword ptr ss:[esp+0x60]
 *  004693d7   52               push edx
 *  004693d8   8b50 40          mov edx,dword ptr ds:[eax+0x40]
 *  004693db   8b86 c8000000    mov eax,dword ptr ds:[esi+0xc8]
 *  004693e1   0386 8c040000    add eax,dword ptr ds:[esi+0x48c]
 *  004693e7   52               push edx
 *  004693e8   50               push eax
 *  004693e9   51               push ecx
 *  004693ea   8bce             mov ecx,esi
 *  004693ec   e8 9fc4ffff      call .00465890
 *  004693f1   39be d00f0000    cmp dword ptr ds:[esi+0xfd0],edi
 *  004693f7   0f85 f2010000    jnz .004695ef
 *  004693fd   8d86 20100000    lea eax,dword ptr ds:[esi+0x1020]
 *  00469403   50               push eax
 *  00469404   55               push ebp
 *  00469405   8bce             mov ecx,esi
 *  00469407   e8 64f4ffff      call .00468870
 *  0046940c   8a4e 25          mov cl,byte ptr ds:[esi+0x25]
 *  0046940f   8a56 26          mov dl,byte ptr ds:[esi+0x26]
 *  00469412   884c24 18        mov byte ptr ss:[esp+0x18],cl
 *  00469416   8b4c24 5c        mov ecx,dword ptr ss:[esp+0x5c]
 *  0046941a   885424 14        mov byte ptr ss:[esp+0x14],dl
 *  0046941e   8b51 40          mov edx,dword ptr ds:[ecx+0x40]
 *  00469421   895424 20        mov dword ptr ss:[esp+0x20],edx
 *  00469425   b9 d0020000      mov ecx,0x2d0
 *  0046942a   2bcb             sub ecx,ebx
 *  0046942c   ba 00000000      mov edx,0x0
 *  00469431   0f98c2           sets dl
 *  00469434   8bf8             mov edi,eax
 *  00469436   8a46 24          mov al,byte ptr ds:[esi+0x24]
 *  00469439   884424 1c        mov byte ptr ss:[esp+0x1c],al
 *  0046943d   4a               dec edx
 *  0046943e   23d1             and edx,ecx
 *  00469440   69d2 000f0000    imul edx,edx,0xf00
 *  00469446   8bca             mov ecx,edx
 *  00469448   894c24 24        mov dword ptr ss:[esp+0x24],ecx
 *  0046944c   85ff             test edi,edi    ; jichi: hook here
 *  0046944e   74 3a            je short .0046948a
 *  00469450   8b5424 14        mov edx,dword ptr ss:[esp+0x14]
 *  00469454   6a 00            push 0x0
 *  00469456   57               push edi
 *  00469457   8d86 c80c0000    lea eax,dword ptr ds:[esi+0xcc8]
 *  0046945d   50               push eax
 *  0046945e   8b4424 24        mov eax,dword ptr ss:[esp+0x24]
 *  00469462   6a 10            push 0x10
 *  00469464   52               push edx
 *  00469465   8b5424 30        mov edx,dword ptr ss:[esp+0x30]
 *  00469469   50               push eax
 *  0046946a   8b4424 38        mov eax,dword ptr ss:[esp+0x38]
 *  0046946e   52               push edx
 *  0046946f   68 000f0000      push 0xf00
 *  00469474   51               push ecx
 *  00469475   8b4c24 4c        mov ecx,dword ptr ss:[esp+0x4c]
 */
bool InsertSyuntadaHook()
{
  const BYTE bytes[] = {
    0x4a,                           // 0046943d   4a               dec edx
    0x23,0xd1,                      // 0046943e   23d1             and edx,ecx
    0x69,0xd2, 0x00,0x0f,0x00,0x00, // 00469440   69d2 000f0000    imul edx,edx,0xf00
    0x8b,0xca,                      // 00469446   8bca             mov ecx,edx
    0x89,0x4c,0x24, 0x24,           // 00469448   894c24 24        mov dword ptr ss:[esp+0x24],ecx
    0x85,0xff,                      // 0046944c   85ff             test edi,edi    ; jichi: hook here
    0x74, 0x3a                      // 0046944e   74 3a            je short .0046948a
  };
  enum { hook_offset = 0x0046944c - 0x0046943d };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  //ITH_GROWL(addr);
  if (!addr) {
    ConsoleOutput("vnreng:Syuntada: pattern not found");
    return false;
  }
  HookParam hp = {};
  hp.addr = addr + hook_offset;
  hp.off = -0x1c;
  hp.length_offset = 1;
  hp.type = BIG_ENDIAN; // 0x4
  ConsoleOutput("vnreng: INSERT Syuntada");
  NewHook(hp, L"Syuntada");

  // TextOutA will produce repeated texts
  ConsoleOutput("vnreng:Syuntada: disable GDI hooks");
  DisableGDIHooks();
  return true;
}

/** jichi 10/31/2014 Adobe Flash Player v10
 *
 *  Sample game: [141031] [ティンクルベル] 輪舞曲Duo
 *
 *  Debug method: Hex utf16 text, then insert hw breakpoints
 *    21:51 3110% hexstr 『何よ utf16
 *    0e30554f8830
 *
 *  There are also UTF-8 strings in the memory. I could not find a good place to hook
 *  using hw breakpoints.
 *
 *  There are lots of matches. One is selected. Then, the enclosing function is selected.
 *  arg1 is the UNICODE text.
 *
 *  Pattern:
 *
 *  0161293a   8bc6             mov eax,esi
 *  0161293c   5e               pop esi
 *  0161293d   c2 0800          retn 0x8
 *
 *  Function starts
 *  01612940   8b4c24 0c        mov ecx,dword ptr ss:[esp+0xc] ; jichi: hook here
 *  01612944   53               push ebx
 *  01612945   55               push ebp
 *  01612946   56               push esi
 *  01612947   57               push edi
 *  01612948   33ff             xor edi,edi
 *  0161294a   85c9             test ecx,ecx
 *  0161294c   0f84 5f010000    je ron2.01612ab1
 *  01612952   397c24 18        cmp dword ptr ss:[esp+0x18],edi
 *  01612956   0f8e ba010000    jle ron2.01612b16
 *  0161295c   8b6c24 14        mov ebp,dword ptr ss:[esp+0x14]
 *  01612960   be 01000000      mov esi,0x1
 *  01612965   eb 09            jmp short ron2.01612970
 *  01612967   8da424 00000000  lea esp,dword ptr ss:[esp]
 *  0161296e   8bff             mov edi,edi
 *  01612970   0fb755 00        movzx edx,word ptr ss:[ebp]
 *  01612974   297424 18        sub dword ptr ss:[esp+0x18],esi
 *  01612978   b8 80000000      mov eax,0x80
 *  0161297d   66:3bd0          cmp dx,ax
 *  01612980   73 15            jnb short ron2.01612997
 *  01612982   297424 20        sub dword ptr ss:[esp+0x20],esi
 *  01612986   0f88 1d010000    js ron2.01612aa9
 *  0161298c   8811             mov byte ptr ds:[ecx],dl
 *  0161298e   03ce             add ecx,esi
 *  01612990   03fe             add edi,esi
 *  01612992   e9 fd000000      jmp ron2.01612a94
 *  01612997   b8 00080000      mov eax,0x800
 *  0161299c   66:3bd0          cmp dx,ax
 *  0161299f   73 2a            jnb short ron2.016129cb
 *  016129a1   836c24 20 02     sub dword ptr ss:[esp+0x20],0x2
 *  016129a6   0f88 fd000000    js ron2.01612aa9
 *  016129ac   8bc2             mov eax,edx
 *  016129ae   c1e8 06          shr eax,0x6
 *  016129b1   24 1f            and al,0x1f
 *  016129b3   0c c0            or al,0xc0
 *  016129b5   8801             mov byte ptr ds:[ecx],al
 *  016129b7   80e2 3f          and dl,0x3f
 *  016129ba   03ce             add ecx,esi
 *  016129bc   80ca 80          or dl,0x80
 *  016129bf   8811             mov byte ptr ds:[ecx],dl
 *  016129c1   03ce             add ecx,esi
 *  016129c3   83c7 02          add edi,0x2
 *  016129c6   e9 c9000000      jmp ron2.01612a94
 *  016129cb   8d82 00280000    lea eax,dword ptr ds:[edx+0x2800]
 *  016129d1   bb ff030000      mov ebx,0x3ff
 *  016129d6   66:3bc3          cmp ax,bx
 *  016129d9   77 7b            ja short ron2.01612a56
 *  016129db   297424 18        sub dword ptr ss:[esp+0x18],esi
 *  016129df   0f88 c4000000    js ron2.01612aa9
 *  016129e5   0fb775 02        movzx esi,word ptr ss:[ebp+0x2]
 *  016129e9   83c5 02          add ebp,0x2
 *  016129ec   8d86 00240000    lea eax,dword ptr ds:[esi+0x2400]
 *  016129f2   66:3bc3          cmp ax,bx
 *  016129f5   77 58            ja short ron2.01612a4f
 *  016129f7   0fb7d2           movzx edx,dx
 *  016129fa   81ea f7d70000    sub edx,0xd7f7
 *  01612a00   0fb7c6           movzx eax,si
 *  01612a03   c1e2 0a          shl edx,0xa
 *  01612a06   03d0             add edx,eax
 *  01612a08   836c24 20 04     sub dword ptr ss:[esp+0x20],0x4
 *  01612a0d   0f88 96000000    js ron2.01612aa9
 *  01612a13   8bc2             mov eax,edx
 *  01612a15   c1e8 12          shr eax,0x12
 *  01612a18   24 07            and al,0x7
 *  01612a1a   0c f0            or al,0xf0
 *  01612a1c   8801             mov byte ptr ds:[ecx],al
 *  01612a1e   8bc2             mov eax,edx
 *  01612a20   c1e8 0c          shr eax,0xc
 *  01612a23   24 3f            and al,0x3f
 *  01612a25   be 01000000      mov esi,0x1
 *  01612a2a   0c 80            or al,0x80
 *  01612a2c   880431           mov byte ptr ds:[ecx+esi],al
 *  01612a2f   03ce             add ecx,esi
 *  01612a31   8bc2             mov eax,edx
 *  01612a33   c1e8 06          shr eax,0x6
 *  01612a36   03ce             add ecx,esi
 *  01612a38   24 3f            and al,0x3f
 *  01612a3a   0c 80            or al,0x80
 *  01612a3c   8801             mov byte ptr ds:[ecx],al
 *  01612a3e   80e2 3f          and dl,0x3f
 *  01612a41   03ce             add ecx,esi
 *  01612a43   80ca 80          or dl,0x80
 *  01612a46   8811             mov byte ptr ds:[ecx],dl
 *  01612a48   03ce             add ecx,esi
 *  01612a4a   83c7 04          add edi,0x4
 *  01612a4d   eb 45            jmp short ron2.01612a94
 *  01612a4f   be 01000000      mov esi,0x1
 *  01612a54   eb 0b            jmp short ron2.01612a61
 *  01612a56   8d82 00240000    lea eax,dword ptr ds:[edx+0x2400]
 *  01612a5c   66:3bc3          cmp ax,bx
 *  01612a5f   77 05            ja short ron2.01612a66
 *  01612a61   ba fdff0000      mov edx,0xfffd
 *  01612a66   836c24 20 03     sub dword ptr ss:[esp+0x20],0x3
 *  01612a6b   78 3c            js short ron2.01612aa9
 *  01612a6d   8bc2             mov eax,edx
 *  01612a6f   c1e8 0c          shr eax,0xc
 *  01612a72   24 0f            and al,0xf
 *  01612a74   0c e0            or al,0xe0
 *  01612a76   8801             mov byte ptr ds:[ecx],al
 *  01612a78   8bc2             mov eax,edx
 *  01612a7a   c1e8 06          shr eax,0x6
 *  01612a7d   03ce             add ecx,esi
 *  01612a7f   24 3f            and al,0x3f
 *  01612a81   0c 80            or al,0x80
 *  01612a83   8801             mov byte ptr ds:[ecx],al
 *  01612a85   80e2 3f          and dl,0x3f
 *  01612a88   03ce             add ecx,esi
 *  01612a8a   80ca 80          or dl,0x80
 *  01612a8d   8811             mov byte ptr ds:[ecx],dl
 *  01612a8f   03ce             add ecx,esi
 *  01612a91   83c7 03          add edi,0x3
 *  01612a94   83c5 02          add ebp,0x2
 *  01612a97   837c24 18 00     cmp dword ptr ss:[esp+0x18],0x0
 *  01612a9c  ^0f8f cefeffff    jg ron2.01612970
 *  01612aa2   8bc7             mov eax,edi
 *  01612aa4   5f               pop edi
 *  01612aa5   5e               pop esi
 *  01612aa6   5d               pop ebp
 *  01612aa7   5b               pop ebx
 *  01612aa8   c3               retn
 *  01612aa9   5f               pop edi
 *  01612aaa   5e               pop esi
 *  01612aab   5d               pop ebp
 *  01612aac   83c8 ff          or eax,0xffffffff
 *  01612aaf   5b               pop ebx
 *  01612ab0   c3               retn
 *  01612ab1   8b4424 18        mov eax,dword ptr ss:[esp+0x18]
 *  01612ab5   85c0             test eax,eax
 *  01612ab7   7e 5d            jle short ron2.01612b16
 *  01612ab9   8b5424 14        mov edx,dword ptr ss:[esp+0x14]
 *  01612abd   8d49 00          lea ecx,dword ptr ds:[ecx]
 *  01612ac0   0fb70a           movzx ecx,word ptr ds:[edx] ; jichi: this is where the text is accessed
 *  01612ac3   be 80000000      mov esi,0x80
 *  01612ac8   48               dec eax
 *  01612ac9   66:3bce          cmp cx,si
 *  01612acc   73 03            jnb short ron2.01612ad1
 *  01612ace   47               inc edi
 *  01612acf   eb 3e            jmp short ron2.01612b0f
 *  01612ad1   be 00080000      mov esi,0x800
 *  01612ad6   66:3bce          cmp cx,si
 *  01612ad9   73 05            jnb short ron2.01612ae0
 *  01612adb   83c7 02          add edi,0x2
 *  01612ade   eb 2f            jmp short ron2.01612b0f
 *  01612ae0   81c1 00280000    add ecx,0x2800
 *  01612ae6   be ff030000      mov esi,0x3ff
 *  01612aeb   66:3bce          cmp cx,si
 *  01612aee   77 1c            ja short ron2.01612b0c
 *  01612af0   83e8 01          sub eax,0x1
 *  01612af3  ^78 b4            js short ron2.01612aa9
 *  01612af5   0fb74a 02        movzx ecx,word ptr ds:[edx+0x2]
 *  01612af9   83c2 02          add edx,0x2
 *  01612afc   81c1 00240000    add ecx,0x2400
 *  01612b02   66:3bce          cmp cx,si
 *  01612b05   77 05            ja short ron2.01612b0c
 *  01612b07   83c7 04          add edi,0x4
 *  01612b0a   eb 03            jmp short ron2.01612b0f
 *  01612b0c   83c7 03          add edi,0x3
 *  01612b0f   83c2 02          add edx,0x2
 *  01612b12   85c0             test eax,eax
 *  01612b14  ^7f aa            jg short ron2.01612ac0
 *  01612b16   8bc7             mov eax,edi
 *  01612b18   5f               pop edi
 *  01612b19   5e               pop esi
 *  01612b1a   5d               pop ebp
 *  01612b1b   5b               pop ebx
 *  01612b1c   c3               retn
 *  01612b1d   cc               int3
 *  01612b1e   cc               int3
 *  01612b1f   cc               int3
 *
 *  Runtime stack:
 *  0019e974   0161640e  return to Ron2.0161640e from Ron2.01612940
 *  0019e978   1216c180  UNICODE "Dat/Chr/HAL_061.swf"
 *  0019e97c   00000013
 *  0019e980   12522838
 *  0019e984   00000013
 *  0019e988   0210da80
 *  0019e98c   0019ecb0
 *  0019e990   0019e9e0
 *  0019e994   0019ea24
 *  0019e998   0019e9cc
 *
 *  Runtime registers:
 *  EAX 12522838
 *  ECX 1216C180 UNICODE "Dat/Chr/HAL_061.swf"
 *  EDX 0C5E9898
 *  EBX 12532838
 *  ESP 0019E974
 *  EBP 00000013
 *  ESI 00000013
 *  EDI 0019E9CC
 *  EIP 01612940 Ron2.01612940
 */
// Skip ASCII garbage such as: Dat/Chr/HAL_061.swf
static bool AdobeFlashFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  // TODO: Remove [0-9a-zA-Z./]{4,} as garbage
  LPCWSTR p = reinterpret_cast<LPCWSTR>(data);
  size_t len = *size / 2;
  for (size_t i = 0; i < len; i++)
    if (p[i] & 0xff00)
      return true;
  return false;
}
bool InsertAdobeFlash10Hook()
{
  const BYTE bytes[] = {
    0x8b,0x4c,0x24, 0x0c,   // 01612940   8b4c24 0c        mov ecx,dword ptr ss:[esp+0xc] ; jichi: hook here
    0x53,                   // 01612944   53               push ebx
    0x55,                   // 01612945   55               push ebp
    0x56,                   // 01612946   56               push esi
    0x57,                   // 01612947   57               push edi
    0x33,0xff,              // 01612948   33ff             xor edi,edi
    0x85,0xc9,              // 0161294a   85c9             test ecx,ecx
    0x0f,0x84 //, 5f010000  // 0161294c   0f84 5f010000    je ron2.01612ab1
  };
  ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), module_base_, module_limit_);
  //addr = 0x01612940;
  //addr = 0x01612AC0;
  if (!addr) {
    ConsoleOutput("vnreng:AdobeFlash10: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.off = 1 * 4; // arg1
  //hp.length_offset = 2 * 4; // arg2 might be the length
  hp.type = USING_UNICODE;
  hp.filter_fun = AdobeFlashFilter;
  ConsoleOutput("vnreng: INSERT Adobe Flash 10");
  NewHook(hp, L"Adobe Flash 10");

  ConsoleOutput("vnreng:AdobeFlash10: disable GDI hooks");
  DisableGDIHooks();
  return true;
}

/** jichi 12/26/2014 Mono
 *  Sample game: [141226] ハーレムめいと
 */
static void SpecialHookMonoString(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  if (MonoString *s = (MonoString *)argof(1, esp_base)) {
    *data = (DWORD)s->chars;
    *len = s->length * 2; // for widechar
    // Adding split is very dangerous which might create millions of threads
    *split = regof(ecx, esp_base);
    //*split = retof(esp_base);
    //*split = argof(2, esp_base);
  }
}

bool InsertMonoHooks()
{
  HMODULE h = ::GetModuleHandleA("mono.dll");
  if (!h)
    return false;

  bool ret = false;

  // mono_unichar2* mono_string_to_utf16       (MonoString *s);
  // char*          mono_string_to_utf8        (MonoString *s);
  const MonoFunction funcs[] = { MONO_FUNCTIONS_INITIALIZER };
  enum { FunctionCount = sizeof(funcs) / sizeof(*funcs) };

  HookParam hp = {};
  for (int i = 0; i < FunctionCount; i++) {
    const auto &it = funcs[i];
    if (FARPROC addr = ::GetProcAddress(h, it.functionName)) {
      hp.addr = (DWORD)addr;
      hp.type = it.hookType;
      hp.off = it.textIndex * 4;
      hp.length_offset = it.lengthIndex * 4;
      hp.text_fun = (HookParam::text_fun_t)it.text_fun;
      ConsoleOutput("vnreng: Mono: INSERT");
      NewHook(hp, it.hookName);
      ret = true;
    }
  }

  if (!ret)
    ConsoleOutput("vnreng: Mono: failed to find function address");
  return ret;
}

/** jichi 7/20/2014 Dolphin
 *  Tested with Dolphin 4.0
 */
bool InsertGCHooks()
{
  // TODO: Add generic hooks
  return InsertVanillawareGCHook();
  //return false;
}

/** jichi 7/20/2014 Vanillaware
 *  Tested game: 朧村正
 *
 *  Debugging method: grep the saving message
 *
 *  1609415e   cc               int3
 *  1609415f   cc               int3
 *  16094160   77 0f            ja short 16094171
 *  16094162   c705 00fb6701 80>mov dword ptr ds:[0x167fb00],0x80216b80
 *  1609416c  -e9 f9be06f1      jmp 0710006a
 *  16094171   8b35 8cf86701    mov esi,dword ptr ds:[0x167f88c]
 *  16094177   81c6 ffffffff    add esi,-0x1
 *  1609417d   8bce             mov ecx,esi
 *  1609417f   81c1 01000000    add ecx,0x1
 *  16094185   f7c1 0000000c    test ecx,0xc000000
 *  1609418b   74 0b            je short 16094198
 *  1609418d   51               push ecx
 *  1609418e   e8 36bff9f2      call 090300c9
 *  16094193   83c4 04          add esp,0x4
 *  16094196   eb 11            jmp short 160941a9
 *  16094198   8bc1             mov eax,ecx
 *  1609419a   81e0 ffffff3f    and eax,0x3fffffff
 *  160941a0   0fb680 00000810  movzx eax,byte ptr ds:[eax+0x10080000] ; jichi: hook here
 *  160941a7   66:90            nop
 *  160941a9   81c6 01000000    add esi,0x1
 *  160941af   8905 80f86701    mov dword ptr ds:[0x167f880],eax
 *  160941b5   813d 80f86701 00>cmp dword ptr ds:[0x167f880],0x0
 *  160941bf   c705 8cf86701 00>mov dword ptr ds:[0x167f88c],0x0
 *  160941c9   8935 90f86701    mov dword ptr ds:[0x167f890],esi
 *  160941cf   7c 14            jl short 160941e5
 *  160941d1   7f 09            jg short 160941dc
 *  160941d3   c605 0cfb6701 02 mov byte ptr ds:[0x167fb0c],0x2
 *  160941da   eb 26            jmp short 16094202
 *  160941dc   c605 0cfb6701 04 mov byte ptr ds:[0x167fb0c],0x4
 *  160941e3   eb 07            jmp short 160941ec
 *  160941e5   c605 0cfb6701 08 mov byte ptr ds:[0x167fb0c],0x8
 *  160941ec   832d 7c4cb101 06 sub dword ptr ds:[0x1b14c7c],0x6
 *  160941f3   e9 20000000      jmp 16094218
 *  160941f8   0188 6b2180e9    add dword ptr ds:[eax+0xe980216b],ecx
 *  160941fe   0e               push cs
 *  160941ff   be 06f1832d      mov esi,0x2d83f106
 *  16094204   7c 4c            jl short 16094252
 *  16094206   b1 01            mov cl,0x1
 *  16094208   06               push es
 *  16094209   e9 c2000000      jmp 160942d0
 *  1609420e   0198 6b2180e9    add dword ptr ds:[eax+0xe980216b],ebx
 *  16094214   f8               clc
 *  16094215   bd 06f1770f      mov ebp,0xf77f106
 *  1609421a   c705 00fb6701 88>mov dword ptr ds:[0x167fb00],0x80216b88
 *  16094224  -e9 41be06f1      jmp 0710006a
 *  16094229   8b0d 90f86701    mov ecx,dword ptr ds:[0x167f890]
 *  1609422f   81c1 01000000    add ecx,0x1
 *  16094235   f7c1 0000000c    test ecx,0xc000000
 *  1609423b   74 0b            je short 16094248
 *  1609423d   51               push ecx
 *  1609423e   e8 86bef9f2      call 090300c9
 *  16094243   83c4 04          add esp,0x4
 *  16094246   eb 11            jmp short 16094259
 *  16094248   8bc1             mov eax,ecx
 *  1609424a   81e0 ffffff3f    and eax,0x3fffffff
 *  16094250   0fb680 00000810  movzx eax,byte ptr ds:[eax+0x10080000]
 *  16094257   66:90            nop
 *  16094259   8b35 90f86701    mov esi,dword ptr ds:[0x167f890]
 *  1609425f   81c6 01000000    add esi,0x1
 *  16094265   8905 80f86701    mov dword ptr ds:[0x167f880],eax
 *  1609426b   8105 8cf86701 01>add dword ptr ds:[0x167f88c],0x1
 *  16094275   813d 80f86701 00>cmp dword ptr ds:[0x167f880],0x0
 *  1609427f   8935 90f86701    mov dword ptr ds:[0x167f890],esi
 *  16094285   7c 14            jl short 1609429b
 *  16094287   7f 09            jg short 16094292
 *  16094289   c605 0cfb6701 02 mov byte ptr ds:[0x167fb0c],0x2
 *  16094290   eb 26            jmp short 160942b8
 *  16094292   c605 0cfb6701 04 mov byte ptr ds:[0x167fb0c],0x4
 *  16094299   eb 07            jmp short 160942a2
 *  1609429b   c605 0cfb6701 08 mov byte ptr ds:[0x167fb0c],0x8
 *  160942a2   832d 7c4cb101 04 sub dword ptr ds:[0x1b14c7c],0x4
 *  160942a9  ^e9 6affffff      jmp 16094218
 *  160942ae   0188 6b2180e9    add dword ptr ds:[eax+0xe980216b],ecx
 *  160942b4   58               pop eax
 *  160942b5   bd 06f1832d      mov ebp,0x2d83f106
 *  160942ba   7c 4c            jl short 16094308
 *  160942bc   b1 01            mov cl,0x1
 *  160942be   04 e9            add al,0xe9
 *  160942c0   0c 00            or al,0x0
 *  160942c2   0000             add byte ptr ds:[eax],al
 *  160942c4   0198 6b2180e9    add dword ptr ds:[eax+0xe980216b],ebx
 *  160942ca   42               inc edx
 *  160942cb   bd 06f1cccc      mov ebp,0xccccf106
 *  160942d0   77 0f            ja short 160942e1
 *  160942d2   c705 00fb6701 98>mov dword ptr ds:[0x167fb00],0x80216b98
 *  160942dc  -e9 89bd06f1      jmp 0710006a
 *  160942e1   8b05 84fb6701    mov eax,dword ptr ds:[0x167fb84]
 *  160942e7   81e0 fcffffff    and eax,0xfffffffc
 *  160942ed   8905 00fb6701    mov dword ptr ds:[0x167fb00],eax
 *  160942f3   832d 7c4cb101 01 sub dword ptr ds:[0x1b14c7c],0x1
 *  160942fa  -e9 11bd06f1      jmp 07100010
 *  160942ff   832d 7c4cb101 01 sub dword ptr ds:[0x1b14c7c],0x1
 *  16094306  ^e9 91f8ffff      jmp 16093b9c
 *  1609430b   cc               int3
 */
namespace { // unnamed

// Return true if the text is a garbage character
inline bool _vanillawaregarbage_ch(char c)
{
  return c == ' ' || c == '.' || c == '/'
      || c >= '0' && c <= '9'
      || c >= 'A' && c <= 'z' // also ignore ASCII 91-96: [ \ ] ^ _ `
  ;
}

// Return true if the text is full of garbage characters
bool _vanillawaregarbage(LPCSTR p)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  for (int count = 0; (*p) && count < MAX_LENGTH; count++, p++)
    if (!_vanillawaregarbage_ch(*p))
      return false;
  return true;
}
} // unnamed namespace

static void SpecialGCHookVanillaware(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value);
  static LPCSTR lasttext;
  if (lasttext != text && *text && !_vanillawaregarbage(text)) {
    lasttext = text;
    *data = (DWORD)text;
    *len = ::strlen(text); // SHIFT-JIS
    *split = regof(ecx, esp_base);
    //*split = FIXED_SPLIT_VALUE;
  }
}

bool InsertVanillawareGCHook()
{
  ConsoleOutput("vnreng: Vanillaware GC: enter");

  const BYTE bytes[] =  {
    0x83,0xc4, 0x04,                // 16094193   83c4 04          add esp,0x4
    0xeb, 0x11,                     // 16094196   eb 11            jmp short 160941a9
    0x8b,0xc1,                      // 16094198   8bc1             mov eax,ecx
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1609419a   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0x80, XX4,            // 160941a0   0fb680 00000810  movzx eax,byte ptr ds:[eax+0x10080000] ; jichi: hook here
    0x66,0x90,                      // 160941a7   66:90            nop
    0x81,0xc6, 0x01,0x00,0x00,0x00  // 160941a9   81c6 01000000    add esi,0x1
    //0x89,05 80f86701      // 160941af   8905 80f86701    mov dword ptr ds:[0x167f880],eax
    //0x81,3d 80f86701 00   // 160941b5   813d 80f86701 00>cmp dword ptr ds:[0x167f880],0x0
    //0xc7,05 8cf86701 00   // 160941bf   c705 8cf86701 00>mov dword ptr ds:[0x167f88c],0x0
    //0x89,35 90f86701      // 160941c9   8935 90f86701    mov dword ptr ds:[0x167f890],esi
    //0x7c, 14              // 160941cf   7c 14            jl short 160941e5
    //0x7f, 09              // 160941d1   7f 09            jg short 160941dc
    //0xc6,05 0cfb6701 02   // 160941d3   c605 0cfb6701 02 mov byte ptr ds:[0x167fb0c],0x2
    //0xeb, 26              // 160941da   eb 26            jmp short 16094202
  };
  enum { memory_offset = 3 }; // 160941a0   0fb680 00000810  movzx eax,byte ptr ds:[eax+0x10080000]
  enum { hook_offset = 0x160941a0 - 0x16094193 };

  DWORD addr = SafeMatchBytesInGCMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Vanillaware GC: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.text_fun = SpecialGCHookVanillaware;
    hp.type = USING_STRING|NO_CONTEXT; // no context is needed to get rid of variant retaddr
    ConsoleOutput("vnreng: Vanillaware GC: INSERT");
    NewHook(hp, L"Vanillaware GC");
  }

  ConsoleOutput("vnreng: Vanillaware GC: leave");
  return addr;
}

/** jichi 7/12/2014 PPSSPP
 *  Tested with PPSSPP 0.9.8.
 */
void SpecialPSPHook(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD offset = *(DWORD *)(esp_base + hp->off);
  LPCSTR text = LPCSTR(offset + hp->user_value);
  static LPCSTR lasttext;
  if (*text) {
    if (hp->user_flags & HPF_IgnoreSameAddress) {
      if (text == lasttext)
        return;
      lasttext = text;
    }
    *data = (DWORD)text;
    // I only considered SHIFT-JIS/UTF-8 case
    if (hp->length_offset == 1)
      *len = 1; // only read 1 byte
    else if (hp->length_offset)
      *len = *(DWORD *)(esp_base + hp->length_offset);
    else
      *len = ::strlen(text); // should only be applied to hp->type|USING_STRING
    if (hp->type & USING_SPLIT) {
      if (hp->type & FIXING_SPLIT)
        *split = FIXED_SPLIT_VALUE;
      else
        *split = *(DWORD *)(esp_base + hp->split);
    }
  }
}

bool InsertPPSSPPHLEHooks()
{
  ConsoleOutput("vnreng: PPSSPP HLE: enter");
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng:PPSSPP HLE: failed to get memory range");
    return false;
  }

  // 0x400000 - 0x139f000
  //ITH_GROWL_DWORD2(startAddress, stopAddress);

  HookParam hp = {};
  hp.length_offset = 1; // determine string length at runtime

  const PPSSPPFunction funcs[] = { PPSSPP_FUNCTIONS_INITIALIZER };
  enum { FunctionCount = sizeof(funcs)/sizeof(*funcs) };
  for (size_t i = 0; i < FunctionCount; i++) {
    const auto &it = funcs[i];
    ULONG addr = MemDbg::findBytes(it.pattern, ::strlen(it.pattern), startAddress, stopAddress);
    if (addr
        && (addr = MemDbg::findPushAddress(addr, startAddress, stopAddress))
        && (addr = SafeFindEnclosingAlignedFunction(addr, 0x200)) // range = 0x200, use the safe version or it might raise
       ) {
       hp.addr = addr;
       hp.type = it.hookType;
       hp.off = 4 * it.argIndex;
       hp.split = it.hookSplit;
       if (hp.split)
         hp.type |= USING_SPLIT;
       NewHook(hp, it.hookName);
    }
    if (addr)
      ConsoleOutput("vnreng: PPSSPP HLE: found pattern");
    else
      ConsoleOutput("vnreng: PPSSPP HLE: not found pattern");
    //ConsoleOutput(it.hookName); // wchar_t not supported
    ConsoleOutput(it.pattern);
  }
  ConsoleOutput("vnreng: PPSSPP HLE: leave");
  return true;
}

bool InsertPPSSPPHooks()
{
  //if (PPSSPP_VERSION[1] == 9 && (PPSSPP_VERSION[2] > 9 || PPSSPP_VERSION[2] == 9 && PPSSPP_VERSION[3] >= 1)) // >= 0.9.9.1

  ConsoleOutput("vnreng: PPSSPP: enter");

  if (!WinVersion::queryFileVersion(process_path_, PPSSPP_VERSION))
    ConsoleOutput("vnreng: failed to get PPSSPP version");

  InsertPPSSPPHLEHooks();

  if (PPSSPP_VERSION[1] == 9 && PPSSPP_VERSION[2] == 9 && PPSSPP_VERSION[3] == 0) // 0.9.9.0
    InsertOtomatePPSSPPHook();

  //bool engineFound = false;
  Insert5pbPSPHook();
  InsertCyberfrontPSPHook();
  InsertImageepoch2PSPHook();
  InsertFelistellaPSPHook();

  InsertBroccoliPSPHook();
  InsertIntensePSPHook();
  //InsertKadokawaNamePSPHook(); // disabled
  InsertKonamiPSPHook();

  if (PPSSPP_VERSION[1] == 9 && PPSSPP_VERSION[2] == 8) { // only works for 0.9.8 anyway
    InsertNippon1PSPHook();
    InsertNippon2PSPHook(); // This could crash PPSSPP 099 just like 5pb
  }

  //InsertTecmoPSPHook();

  // Generic hooks

  bool bandaiFound = InsertBandaiPSPHook();
  InsertBandaiNamePSPHook();

  // Hooks whose pattern is not generic enouph

  InsertYetiPSPHook();
  InsertYeti2PSPHook();

  InsertAlchemistPSPHook();
  InsertAlchemist2PSPHook();

  //InsertTypeMoonPSPHook() // otomate is creating too many garbage
  //|| InsertOtomatePSPHook();
  InsertOtomatePSPHook();

  if (!bandaiFound) {
    // KID pattern is a subset of BANDAI, and hence MUST NOT be together with BANDAI
    // Sample BANDAI game that could be broken by KID: 密室のサクリファイス
    InsertKidPSPHook(); // KID could lose text, could exist in multiple game

    InsertImageepochPSPHook();  // Imageepoch could crash vnrcli for School Rumble PSP
  }

  ConsoleOutput("vnreng: PPSSPP: leave");
  return true;
}

/** 7/13/2014 jichi alchemist-net.co.jp PSP engine, 0.9.8 only, not work on 0.9.9
 *  Sample game: your diary+ (moe-ydp.iso)
 *  The memory address is fixed.
 *  Note: This pattern seems to be common that not only exists in Alchemist games.
 *
 *  Not work on 0.9.9: Amnesia Crowd
 *
 *  Debug method: simply add hardware break points to the matched memory
 *
 *  PPSSPP 0.9.8, your diary+
 *  134076f2   cc               int3
 *  134076f3   cc               int3
 *  134076f4   77 0f            ja short 13407705
 *  134076f6   c705 a8aa1001 40>mov dword ptr ds:[0x110aaa8],0x8931040
 *  13407700  -e9 ff88f2f3      jmp 07330004
 *  13407705   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  1340770b   81e0 ffffff3f    and eax,0x3fffffff
 *  13407711   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000]   // jichi: hook here
 *  13407718   8b3d 78a71001    mov edi,dword ptr ds:[0x110a778]
 *  1340771e   8b2d 7ca71001    mov ebp,dword ptr ds:[0x110a77c]
 *  13407724   81c5 01000000    add ebp,0x1
 *  1340772a   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  13407730   81e0 ffffff3f    and eax,0x3fffffff
 *  13407736   8bd6             mov edx,esi
 *  13407738   8890 00004007    mov byte ptr ds:[eax+0x7400000],dl      // jichi: alternatively hook here
 *  1340773e   8b15 78a71001    mov edx,dword ptr ds:[0x110a778]
 *  13407744   81c2 01000000    add edx,0x1
 *  1340774a   8bcd             mov ecx,ebp
 *  1340774c   8935 88a71001    mov dword ptr ds:[0x110a788],esi
 *  13407752   8bf2             mov esi,edx
 *  13407754   813d 88a71001 00>cmp dword ptr ds:[0x110a788],0x0
 *  1340775e   893d 70a71001    mov dword ptr ds:[0x110a770],edi
 *  13407764   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  1340776a   890d 7ca71001    mov dword ptr ds:[0x110a77c],ecx
 *  13407770   8915 80a71001    mov dword ptr ds:[0x110a780],edx
 *  13407776   892d 84a71001    mov dword ptr ds:[0x110a784],ebp
 *  1340777c   0f85 16000000    jnz 13407798
 *  13407782   832d c4aa1001 08 sub dword ptr ds:[0x110aac4],0x8
 *  13407789   e9 ce000000      jmp 1340785c
 *  1340778e   017c10 93        add dword ptr ds:[eax+edx-0x6d],edi
 *  13407792   08e9             or cl,ch
 *  13407794   8b88 f2f3832d    mov ecx,dword ptr ds:[eax+0x2d83f3f2]
 *  1340779a   c4aa 100108e9    les ebp,fword ptr ds:[edx+0xe9080110]    ; modification of segment register
 *  134077a0   0c 00            or al,0x0
 *  134077a2   0000             add byte ptr ds:[eax],al
 *  134077a4   0160 10          add dword ptr ds:[eax+0x10],esp
 *  134077a7   93               xchg eax,ebx
 *  134077a8   08e9             or cl,ch
 *  134077aa  ^75 88            jnz short 13407734
 *  134077ac   f2:              prefix repne:                            ; superfluous prefix
 *  134077ad   f3:              prefix rep:                              ; superfluous prefix
 *  134077ae   90               nop
 *  134077af   cc               int3
 */

namespace { // unnamed

// Return true if the text is a garbage character
inline bool _alchemistgarbage_ch(char c)
{
  return c == '.' || c == '/'
      || c == '#' || c == ':' // garbage in alchemist2 hook
      || c >= '0' && c <= '9'
      || c >= 'A' && c <= 'z' // also ignore ASCII 91-96: [ \ ] ^ _ `
  ;
}

// Return true if the text is full of garbage characters
bool _alchemistgarbage(LPCSTR p)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  for (int count = 0; (*p) && count < MAX_LENGTH; count++, p++)
    if (!_alchemistgarbage_ch(*p))
      return false;
  return true;
}

// 7/20/2014 jichi: Trim Rejet garbage. Sample game: 月華繚乱ROMANCE
// Such as: #Pos[1,2]
inline bool _rejetgarbage_ch(char c)
{
  return c == '#' || c == ' ' || c == '[' || c == ']' || c == ','
      || c >= 'A' && c <= 'z' // also ignore ASCII 91-96: [ \ ] ^ _ `
      || c >= '0' && c <= '9';
}

bool _rejetgarbage(LPCSTR p)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  for (int count = 0; (*p) && count < MAX_LENGTH; count++, p++)
    if (!_rejetgarbage_ch(*p))
      return false;
  return true;
}

// Trim leading garbage
LPCSTR _rejetltrim(LPCSTR p)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  if (p)
    for (int count = 0; (*p) && count < MAX_LENGTH; count++, p++)
      if (!_rejetgarbage_ch(*p))
        return p;
  return nullptr;
}

// Trim trailing garbage
size_t _rejetstrlen(LPCSTR text)
{
  if (!text)
    return 0;
  size_t len = ::strlen(text),
         ret = len;
  while (len && _rejetgarbage_ch(text[len - 1])) {
    len--;
    if (text[len] == '#') // in case trim UTF-8 trailing bytes
      ret = len;
  }
  return ret;
}

} // unnamed namespace

static void SpecialPSPHookAlchemist(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value);
  if (*text && !_alchemistgarbage(text)) {
    text = _rejetltrim(text);
    *data = (DWORD)text;
    *len = _rejetstrlen(text);
    *split = regof(ecx, esp_base);
  }
}

bool InsertAlchemistPSPHook()
{
  ConsoleOutput("vnreng: Alchemist PSP: enter");
  const BYTE bytes[] =  {
     //0xcc,                         // 134076f2   cc               int3
     //0xcc,                         // 134076f3   cc               int3
     0x77, 0x0f,                     // 134076f4   77 0f            ja short 13407705
     0xc7,0x05, XX8,                 // 134076f6   c705 a8aa1001 40>mov dword ptr ds:[0x110aaa8],0x8931040
     0xe9, XX4,                      // 13407700  -e9 ff88f2f3      jmp 07330004
     0x8b,0x05, XX4,                 // 13407705   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
     0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1340770b   81e0 ffffff3f    and eax,0x3fffffff
     0x0f,0xbe,0xb0, XX4,            // 13407711   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000]   // jichi: hook here
     0x8b,0x3d, XX4,                 // 13407718   8b3d 78a71001    mov edi,dword ptr ds:[0x110a778]
     0x8b,0x2d, XX4,                 // 1340771e   8b2d 7ca71001    mov ebp,dword ptr ds:[0x110a77c]
     0x81,0xc5, 0x01,0x00,0x00,0x00, // 13407724   81c5 01000000    add ebp,0x1
     0x8b,0x05, XX4,                 // 1340772a   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
     0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13407730   81e0 ffffff3f    and eax,0x3fffffff
     0x8b,0xd6,                      // 13407736   8bd6             mov edx,esi
     0x88,0x90 //, XX4               // 13407738   8890 00004007    mov byte ptr ds:[eax+0x7400000],dl      // jichi: alternatively hook here
  };
  enum { memory_offset = 3 }; // 13407711   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000]
  enum { hook_offset = 0x13407711 - 0x134076f4 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  //ITH_GROWL_DWORD(addr);
  if (!addr)
    ConsoleOutput("vnreng: Alchemist PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.text_fun = SpecialPSPHookAlchemist;
    hp.type = USING_STRING|NO_CONTEXT; // no context is needed to get rid of variant retaddr
    ConsoleOutput("vnreng: Alchemist PSP: INSERT");
    NewHook(hp, L"Alchemist PSP");
  }

  ConsoleOutput("vnreng: Alchemist PSP: leave");
  return addr;
}

/** 7/20/2014 jichi alchemist-net.co.jp PSP engine, 0.9.8, 0.9.9
 *  An alternative alchemist hook for old alchemist games.
 *  Sample game: のーふぇいと (No Fate)
 *  The memory address is fixed.
 *
 *  Also work on 0.9.9 Otoboku PSP
 *
 *  Debug method: simply add hardware break points to the matched memory
 *
 *  Two candidate functions are seems OK.
 *
 *  Instruction pattern: 81e580808080    // and ebp,0x80808080
 *
 *  0.9.8 のーふぇいと
 *  13400ef3   90               nop
 *  13400ef4   77 0f            ja short 13400f05
 *  13400ef6   c705 a8aa1001 d0>mov dword ptr ds:[0x110aaa8],0x889aad0
 *  13400f00  -e9 fff050f0      jmp 03910004
 *  13400f05   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
 *  13400f0b   8bc6             mov eax,esi
 *  13400f0d   81e0 ffffff3f    and eax,0x3fffffff
 *  13400f13   8bb8 00004007    mov edi,dword ptr ds:[eax+0x7400000] ; jichi
 *  13400f19   8bef             mov ebp,edi
 *  13400f1b   81ed 01010101    sub ebp,0x1010101
 *  13400f21   f7d7             not edi
 *  13400f23   23ef             and ebp,edi
 *  13400f25   81e5 80808080    and ebp,0x80808080
 *  13400f2b   81fd 00000000    cmp ebp,0x0
 *  13400f31   c705 78a71001 80>mov dword ptr ds:[0x110a778],0x80808080
 *  13400f3b   c705 7ca71001 01>mov dword ptr ds:[0x110a77c],0x1010101
 *  13400f45   8935 80a71001    mov dword ptr ds:[0x110a780],esi
 *  13400f4b   892d 88a71001    mov dword ptr ds:[0x110a788],ebp
 *  13400f51   0f84 22000000    je 13400f79
 *  13400f57   8b35 80a71001    mov esi,dword ptr ds:[0x110a780]
 *  13400f5d   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  13400f63   832d c4aa1001 0c sub dword ptr ds:[0x110aac4],0xc
 *  13400f6a   e9 35ba0000      jmp 1340c9a4
 *  13400f6f   0124ab           add dword ptr ds:[ebx+ebp*4],esp
 *  13400f72   8908             mov dword ptr ds:[eax],ecx
 *  13400f74  -e9 aaf050f0      jmp 03910023
 *  13400f79   832d c4aa1001 0c sub dword ptr ds:[0x110aac4],0xc
 *  13400f80   e9 0b000000      jmp 13400f90
 *  13400f85   0100             add dword ptr ds:[eax],eax
 *  13400f87   ab               stos dword ptr es:[edi]
 *  13400f88   8908             mov dword ptr ds:[eax],ecx
 *  13400f8a  -e9 94f050f0      jmp 03910023
 *  13400f8f   90               nop
 */

static void SpecialPSPHookAlchemist2(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value);
  if (*text && !_alchemistgarbage(text)) {
    *data = (DWORD)text;
    *len = ::strlen(text);
    *split = regof(ecx, esp_base);
  }
}

bool InsertAlchemist2PSPHook()
{
  ConsoleOutput("vnreng: Alchemist2 PSP: enter");
  const BYTE bytes[] =  {
    0x77, 0x0f,                     // 13400ef4   77 0f            ja short 13400f05
    0xc7,0x05, XX8,                 // 13400ef6   c705 a8aa1001 d0>mov dword ptr ds:[0x110aaa8],0x889aad0
    0xe9, XX4,                      // 13400f00  -e9 fff050f0      jmp 03910004
    0x8b,0x35, XX4,                 // 13400f05   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
    0x8b,0xc6,                      // 13400f0b   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13400f0d   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xb8, XX4,                 // 13400f13   8bb8 00004007    mov edi,dword ptr ds:[eax+0x7400000] ; jichi: hook here
    0x8b,0xef,                      // 13400f19   8bef             mov ebp,edi
    0x81,0xed, 0x01,0x01,0x01,0x01, // 13400f1b   81ed 01010101    sub ebp,0x1010101
    0xf7,0xd7,                      // 13400f21   f7d7             not edi
    0x23,0xef,                      // 13400f23   23ef             and ebp,edi
    0x81,0xe5, 0x80,0x80,0x80,0x80, // 13400f25   81e5 80808080    and ebp,0x80808080
    0x81,0xfd, 0x00,0x00,0x00,0x00  // 13400f2b   81fd 00000000    cmp ebp,0x0
  };
  enum { memory_offset = 2 }; // 13400f13   8bb8 00004007    mov edi,dword ptr ds:[eax+0x7400000]
  enum { hook_offset = 0x13400f13 - 0x13400ef4 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  //ITH_GROWL_DWORD(addr);
  if (!addr)
    ConsoleOutput("vnreng: Alchemist2 PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.text_fun = SpecialPSPHookAlchemist2;
    hp.type = USING_STRING|NO_CONTEXT; // no context is needed to get rid of variant retaddr
    ConsoleOutput("vnreng: Alchemist2 PSP: INSERT");
    NewHook(hp, L"Alchemist2 PSP");
  }

  ConsoleOutput("vnreng: Alchemist2 PSP: leave");
  return addr;
}

/** 7/13/2014 jichi 5pb.jp PSP engine, 0.9.8, 0.9.9
 *  Sample game: STEINS;GATE
 *
 *  FIXME: The current pattern could crash VNR
 *
 *  Note: searching after 0x15000000 would found a wrong address on 0.9.9.
 *  Hooking to it would crash PPSSPP.
 *
 *  Float memory addresses: two matches
 *
 *  Debug method: precompute memory address and set break points, then navigate to that scene
 *
 *  Attach to this function for wrong game might cause BEX (buffer overflow) exception.
 *
 *  135752c7   90               nop
 *  135752c8   77 0f            ja short 135752d9
 *  135752ca   c705 a8aa1001 d4>mov dword ptr ds:[0x110aaa8],0x8888ed4
 *  135752d4  -e9 2badf3ef      jmp 034b0004
 *  135752d9   8b35 dca71001    mov esi,dword ptr ds:[0x110a7dc]
 *  135752df   8d76 a0          lea esi,dword ptr ds:[esi-0x60]
 *  135752e2   8b3d e4a71001    mov edi,dword ptr ds:[0x110a7e4]
 *  135752e8   8bc6             mov eax,esi
 *  135752ea   81e0 ffffff3f    and eax,0x3fffffff
 *  135752f0   89b8 1c004007    mov dword ptr ds:[eax+0x740001c],edi
 *  135752f6   8b2d bca71001    mov ebp,dword ptr ds:[0x110a7bc]
 *  135752fc   8bc6             mov eax,esi
 *  135752fe   81e0 ffffff3f    and eax,0x3fffffff
 *  13575304   89a8 18004007    mov dword ptr ds:[eax+0x7400018],ebp
 *  1357530a   8b15 b8a71001    mov edx,dword ptr ds:[0x110a7b8]
 *  13575310   8bc6             mov eax,esi
 *  13575312   81e0 ffffff3f    and eax,0x3fffffff
 *  13575318   8990 14004007    mov dword ptr ds:[eax+0x7400014],edx
 *  1357531e   8b0d b4a71001    mov ecx,dword ptr ds:[0x110a7b4]
 *  13575324   8bc6             mov eax,esi
 *  13575326   81e0 ffffff3f    and eax,0x3fffffff
 *  1357532c   8988 10004007    mov dword ptr ds:[eax+0x7400010],ecx
 *  13575332   8b3d b0a71001    mov edi,dword ptr ds:[0x110a7b0]
 *  13575338   8bc6             mov eax,esi
 *  1357533a   81e0 ffffff3f    and eax,0x3fffffff
 *  13575340   89b8 0c004007    mov dword ptr ds:[eax+0x740000c],edi
 *  13575346   8b3d aca71001    mov edi,dword ptr ds:[0x110a7ac]
 *  1357534c   8bc6             mov eax,esi
 *  1357534e   81e0 ffffff3f    and eax,0x3fffffff
 *  13575354   89b8 08004007    mov dword ptr ds:[eax+0x7400008],edi
 *  1357535a   8b3d a8a71001    mov edi,dword ptr ds:[0x110a7a8]
 *  13575360   8bc6             mov eax,esi
 *  13575362   81e0 ffffff3f    and eax,0x3fffffff
 *  13575368   89b8 04004007    mov dword ptr ds:[eax+0x7400004],edi
 *  1357536e   8b15 78a71001    mov edx,dword ptr ds:[0x110a778]
 *  13575374   8935 dca71001    mov dword ptr ds:[0x110a7dc],esi
 *  1357537a   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  13575380   81e0 ffffff3f    and eax,0x3fffffff
 *  13575386   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
 *  1357538d   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  13575393   8b35 80a71001    mov esi,dword ptr ds:[0x110a780]
 *  13575399   8935 b0a71001    mov dword ptr ds:[0x110a7b0],esi
 *  1357539f   8b35 84a71001    mov esi,dword ptr ds:[0x110a784]
 *  135753a5   8b0d 7ca71001    mov ecx,dword ptr ds:[0x110a77c]
 *  135753ab   813d 78a71001 00>cmp dword ptr ds:[0x110a778],0x0
 *  135753b5   c705 a8a71001 00>mov dword ptr ds:[0x110a7a8],0x0
 *  135753bf   8935 aca71001    mov dword ptr ds:[0x110a7ac],esi
 *  135753c5   890d b4a71001    mov dword ptr ds:[0x110a7b4],ecx
 *  135753cb   8915 b8a71001    mov dword ptr ds:[0x110a7b8],edx
 *  135753d1   0f85 16000000    jnz 135753ed
 *  135753d7   832d c4aa1001 0f sub dword ptr ds:[0x110aac4],0xf
 *  135753de   e9 e5010000      jmp 135755c8
 *  135753e3   01f0             add eax,esi
 *  135753e5   90               nop
 *  135753e6   8808             mov byte ptr ds:[eax],cl
 *  135753e8  -e9 36acf3ef      jmp 034b0023
 *  135753ed   832d c4aa1001 0f sub dword ptr ds:[0x110aac4],0xf
 *  135753f4   e9 0b000000      jmp 13575404
 *  135753f9   0110             add dword ptr ds:[eax],edx
 *  135753fb   8f               ???                                      ; unknown command
 *  135753fc   8808             mov byte ptr ds:[eax],cl
 *  135753fe  -e9 20acf3ef      jmp 034b0023
 *  13575403   90               nop
 *  13575404   77 0f            ja short 13575415
 *  13575406   c705 a8aa1001 10>mov dword ptr ds:[0x110aaa8],0x8888f10
 *  13575410  -e9 efabf3ef      jmp 034b0004
 *  13575415   8b35 a8a71001    mov esi,dword ptr ds:[0x110a7a8]
 *  1357541b   33c0             xor eax,eax
 *  1357541d   3b35 b0a71001    cmp esi,dword ptr ds:[0x110a7b0]
 *  13575423   0f9cc0           setl al
 *  13575426   8bf8             mov edi,eax
 *  13575428   81ff 00000000    cmp edi,0x0
 *  1357542e   893d 74a71001    mov dword ptr ds:[0x110a774],edi
 *  13575434   0f84 22000000    je 1357545c
 *  1357543a   8b35 b4a71001    mov esi,dword ptr ds:[0x110a7b4]
 *  13575440   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  13575446   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  1357544d   c705 a8aa1001 2c>mov dword ptr ds:[0x110aaa8],0x8888f2c
 *  13575457  -e9 c7abf3ef      jmp 034b0023
 *  1357545c   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  13575463   e9 0c000000      jmp 13575474
 *  13575468   011c8f           add dword ptr ds:[edi+ecx*4],ebx
 *  1357546b   8808             mov byte ptr ds:[eax],cl
 *  1357546d  -e9 b1abf3ef      jmp 034b0023
 *  13575472   90               nop
 *  13575473   cc               int3
 *  13575474   77 0f            ja short 13575485
 *  13575476   c705 a8aa1001 1c>mov dword ptr ds:[0x110aaa8],0x8888f1c
 *  13575480  -e9 7fabf3ef      jmp 034b0004
 *  13575485   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
 *  1357548b   8b05 b8a71001    mov eax,dword ptr ds:[0x110a7b8]
 *  13575491   81e0 ffffff3f    and eax,0x3fffffff
 *  13575497   8bd6             mov edx,esi
 *  13575499   8890 00004007    mov byte ptr ds:[eax+0x7400000],dl
 *  1357549f   8b3d b4a71001    mov edi,dword ptr ds:[0x110a7b4]
 *  135754a5   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
 *  135754a8   8b2d b8a71001    mov ebp,dword ptr ds:[0x110a7b8]
 *  135754ae   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  135754b1   813d 68a71001 00>cmp dword ptr ds:[0x110a768],0x0
 *  135754bb   893d b4a71001    mov dword ptr ds:[0x110a7b4],edi
 *  135754c1   892d b8a71001    mov dword ptr ds:[0x110a7b8],ebp
 *  135754c7   0f85 16000000    jnz 135754e3
 *  135754cd   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  135754d4   e9 23000000      jmp 135754fc
 *  135754d9   01e4             add esp,esp
 *  135754db   90               nop
 *  135754dc   8808             mov byte ptr ds:[eax],cl
 *  135754de  -e9 40abf3ef      jmp 034b0023
 *  135754e3   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  135754ea   c705 a8aa1001 2c>mov dword ptr ds:[0x110aaa8],0x8888f2c
 *  135754f4  -e9 2aabf3ef      jmp 034b0023
 *  135754f9   90               nop
 *  135754fa   cc               int3
 *  135754fb   cc               int3
 */
namespace { // unnamed

// Characters to ignore: [%0-9A-Z]
inline bool _5pbgarbage_ch(char c)
{ return c == '%' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'; }

// Trim leading garbage
LPCSTR _5pbltrim(LPCSTR p)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  if (p)
    for (int count = 0; (*p) && count < MAX_LENGTH; count++, p++)
      if (!_5pbgarbage_ch(*p))
        return p;
  return nullptr;
}

// Trim trailing garbage
size_t _5pbstrlen(LPCSTR text)
{
  if (!text)
    return 0;
  size_t len = ::strlen(text),
         ret = len;
  while (len && _5pbgarbage_ch(text[len - 1])) {
    len--;
    if (text[len] == '%') // in case trim UTF-8 trailing bytes
      ret = len;
  }
  return ret;
}

} // unnamed namespace

static void SpecialPSPHook5pb(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value);
  if (*text) {
    text = _5pbltrim(text);
    *data = (DWORD)text;
    *len = _5pbstrlen(text);
    *split = regof(ecx, esp_base);
    //*split = FIXED_SPLIT_VALUE; // there is only one thread, no split used
  }
}

bool Insert5pbPSPHook()
{
  ConsoleOutput("vnreng: 5pb PSP: enter");

  const BYTE bytes[] =  {
    //0x90,                         // 135752c7   90               nop
    0x77, 0x0f,                     // 135752c8   77 0f            ja short 135752d9
    0xc7,0x05, XX8,                 // 135752ca   c705 a8aa1001 d4>mov dword ptr ds:[0x110aaa8],0x8888ed4
    0xe9, XX4,                      // 135752d4  -e9 2badf3ef      jmp 034b0004
    0x8b,0x35, XX4,                 // 135752d9   8b35 dca71001    mov esi,dword ptr ds:[0x110a7dc]
    0x8d,0x76, 0xa0,                // 135752df   8d76 a0          lea esi,dword ptr ds:[esi-0x60]
    0x8b,0x3d, XX4,                 // 135752e2   8b3d e4a71001    mov edi,dword ptr ds:[0x110a7e4]
    0x8b,0xc6,                      // 135752e8   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 135752ea   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0xb8, XX4,                 // 135752f0   89b8 1c004007    mov dword ptr ds:[eax+0x740001c],edi
    0x8b,0x2d, XX4,                 // 135752f6   8b2d bca71001    mov ebp,dword ptr ds:[0x110a7bc]
    0x8b,0xc6,                      // 135752fc   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 135752fe   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0xa8, XX4,                 // 13575304   89a8 18004007    mov dword ptr ds:[eax+0x7400018],ebp
    0x8b,0x15, XX4,                 // 1357530a   8b15 b8a71001    mov edx,dword ptr ds:[0x110a7b8]
    0x8b,0xc6,                      // 13575310   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13575312   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0x90, XX4,                 // 13575318   8990 14004007    mov dword ptr ds:[eax+0x7400014],edx
    0x8b,0x0d, XX4,                 // 1357531e   8b0d b4a71001    mov ecx,dword ptr ds:[0x110a7b4]
    0x8b,0xc6,                      // 13575324   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13575326   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0x88, XX4,                 // 1357532c   8988 10004007    mov dword ptr ds:[eax+0x7400010],ecx
    0x8b,0x3d, XX4,                 // 13575332   8b3d b0a71001    mov edi,dword ptr ds:[0x110a7b0]
    0x8b,0xc6,                      // 13575338   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1357533a   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0xb8, XX4,                 // 13575340   89b8 0c004007    mov dword ptr ds:[eax+0x740000c],edi
    0x8b,0x3d, XX4,                 // 13575346   8b3d aca71001    mov edi,dword ptr ds:[0x110a7ac]
    0x8b,0xc6,                      // 1357534c   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1357534e   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0xb8, XX4,                 // 13575354   89b8 08004007    mov dword ptr ds:[eax+0x7400008],edi
    0x8b,0x3d, XX4,                 // 1357535a   8b3d a8a71001    mov edi,dword ptr ds:[0x110a7a8]
    0x8b,0xc6,                      // 13575360   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13575362   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0xb8, XX4,                 // 13575368   89b8 04004007    mov dword ptr ds:[eax+0x7400004],edi
    0x8b,0x15, XX4,                 // 1357536e   8b15 78a71001    mov edx,dword ptr ds:[0x110a778]
    0x89,0x35, XX4,                 // 13575374   8935 dca71001    mov dword ptr ds:[0x110a7dc],esi
    0x8b,0x05, XX4,                 // 1357537a   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13575380   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xbe,0xb0 //, XX4          // 13575386   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
  };
  enum { memory_offset = 3 }; // 13575386   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000]
  enum { hook_offset = sizeof(bytes) - memory_offset };

  enum : DWORD { start = MemDbg::MappedMemoryStartAddress };
  DWORD stop = PPSSPP_VERSION[1] == 9 && PPSSPP_VERSION[2] == 8 ? MemDbg::MemoryStopAddress : 0x15000000;
  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes), start, stop);
  //ITH_GROWL_DWORD(addr);
  if (!addr)
    ConsoleOutput("vnreng: 5pb PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.text_fun = SpecialPSPHook5pb;
    hp.type = USING_STRING|NO_CONTEXT; // no context is needed to get rid of variant retaddr
    ConsoleOutput("vnreng: 5pb PSP: INSERT");
    NewHook(hp, L"5pb PSP");
  }

  ConsoleOutput("vnreng: 5pb PSP: leave");
  return addr;
}

/** 7/13/2014 jichi imageepoch.co.jp PSP engine, 0.9.8, 0.9.9
 *  Sample game: BLACK☆ROCK SHOOTER
 *
 *  Float memory addresses: two matches, UTF-8
 *
 *  7/29/2014: seems to work on 0.9.9
 *
 *  Debug method: find current sentence, then find next sentence in the memory
 *  and add break-points
 *
 *  1346d34b   f0:90            lock nop                                 ; lock prefix is not allowed
 *  1346d34d   cc               int3
 *  1346d34e   cc               int3
 *  1346d34f   cc               int3
 *  1346d350   77 0f            ja short 1346d361
 *  1346d352   c705 a8aa1001 e4>mov dword ptr ds:[0x110aaa8],0x89609e4
 *  1346d35c  -e9 a32c27f0      jmp 036e0004
 *  1346d361   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  1346d367   81e0 ffffff3f    and eax,0x3fffffff
 *  1346d36d   8bb0 00004007    mov esi,dword ptr ds:[eax+0x7400000] ; jichi: or hook here
 *  1346d373   8b3d 78a71001    mov edi,dword ptr ds:[0x110a778]
 *  1346d379   8bc6             mov eax,esi
 *  1346d37b   81e0 ffffff3f    and eax,0x3fffffff
 *  1346d381   0fb6a8 00004007  movzx ebp,byte ptr ds:[eax+0x7400000] ; jichi: hook here
 *  1346d388   8d56 01          lea edx,dword ptr ds:[esi+0x1]
 *  1346d38b   8bc5             mov eax,ebp
 *  1346d38d   0fbec8           movsx ecx,al
 *  1346d390   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  1346d396   8bf5             mov esi,ebp
 *  1346d398   81f9 00000000    cmp ecx,0x0
 *  1346d39e   892d 74a71001    mov dword ptr ds:[0x110a774],ebp
 *  1346d3a4   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  1346d3aa   8915 7ca71001    mov dword ptr ds:[0x110a77c],edx
 *  1346d3b0   890d 80a71001    mov dword ptr ds:[0x110a780],ecx
 *  1346d3b6   893d 84a71001    mov dword ptr ds:[0x110a784],edi
 *  1346d3bc   0f8d 16000000    jge 1346d3d8
 *  1346d3c2   832d c4aa1001 07 sub dword ptr ds:[0x110aac4],0x7
 *  1346d3c9   e9 22000000      jmp 1346d3f0
 *  1346d3ce   010c0a           add dword ptr ds:[edx+ecx],ecx
 *  1346d3d1   96               xchg eax,esi
 *  1346d3d2   08e9             or cl,ch
 *  1346d3d4   4b               dec ebx
 *  1346d3d5   2c 27            sub al,0x27
 *  1346d3d7   f0:832d c4aa1001>lock sub dword ptr ds:[0x110aac4],0x7    ; lock prefix
 *  1346d3df   e9 bc380000      jmp 13470ca0
 *  1346d3e4   0100             add dword ptr ds:[eax],eax
 *  1346d3e6   0a96 08e9352c    or dl,byte ptr ds:[esi+0x2c35e908]
 *  1346d3ec   27               daa
 *  1346d3ed   f0:90            lock nop                                 ; lock prefix is not allowed
 *  1346d3ef   cc               int3
 */
static void SpecialPSPHookImageepoch(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  // 7/25/2014: I tried using uniquemap to eliminate duplication, which does not work
  DWORD eax = regof(eax, esp_base);
  DWORD text = eax + hp->user_value;
  static DWORD lasttext; // Prevent reading the same address multiple times
  if (text != lasttext && *(LPCSTR)text) {
    *data = lasttext = text;
    *len = ::strlen((LPCSTR)text); // UTF-8 is null-terminated
    *split = regof(ecx, esp_base); // use ecx = "this" to split?
  }
}

bool InsertImageepochPSPHook()
{
  ConsoleOutput("vnreng: Imageepoch PSP: enter");

  const BYTE bytes[] =  {
    //0xcc,                         // 1346d34f   cc               int3
    0x77, 0x0f,                     // 1346d350   77 0f            ja short 1346d361
    0xc7,0x05, XX8,                 // 1346d352   c705 a8aa1001 e4>mov dword ptr ds:[0x110aaa8],0x89609e4
    0xe9, XX4,                      // 1346d35c  -e9 a32c27f0      jmp 036e0004
    0x8b,0x05, XX4,                 // 1346d361   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1346d367   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xb0, XX4,                 // 1346d36d   8bb0 00004007    mov esi,dword ptr ds:[eax+0x7400000] ; jichi: or hook here
    0x8b,0x3d, XX4,                 // 1346d373   8b3d 78a71001    mov edi,dword ptr ds:[0x110a778]
    0x8b,0xc6,                      // 1346d379   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1346d37b   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xa8, XX4,            // 1346d381   0fb6a8 00004007  movzx ebp,byte ptr ds:[eax+0x7400000] ; jichi: hook here
    0x8d,0x56, 0x01,                // 1346d388   8d56 01          lea edx,dword ptr ds:[esi+0x1]
    0x8b,0xc5,                      // 1346d38b   8bc5             mov eax,ebp
    0x0f,0xbe,0xc8                  // 1346d38d   0fbec8           movsx ecx,al
  };
  enum { memory_offset = 3 }; // 1346d381   0fb6a8 00004007  movzx ebp,byte ptr ds:[eax+0x7400000]
  enum { hook_offset = 0x1346d381 - 0x1346d350 };
  //enum { hook_offset = sizeof(bytes) - memory_offset };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Imageepoch PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT; // UTF-8, though
    hp.off = pusha_eax_off - 4;
    hp.split = pusha_ecx_off - 4;
    hp.user_flags = HPF_IgnoreSameAddress;
    //hp.text_fun = SpecialPSPHook;
    hp.text_fun = SpecialPSPHookImageepoch; // since this function is common, use its own static lasttext for HPF_IgnoreSameAddress
    ConsoleOutput("vnreng: Imageepoch PSP: INSERT");
    NewHook(hp, L"Imageepoch PSP");
  }

  ConsoleOutput("vnreng: Imageepoch PSP: leave");
  return addr;
}

/** 8/9/2014 jichi imageepoch.co.jp PSP engine, 0.9.8, 0.9.9
 *  Sample game: Sol Trigger (0.9.8, 0.9.9)
 *
 *  Though Imageepoch1 also exists, it cannot find scenario text.
 *
 *  FIXED memory addresses (different from Imageepoch1): two matches, UTF-8
 *
 *  Debug method: find current text and add breakpoint.
 *
 *  There a couple of good functions. The first one is used.
 *  There is only one text threads. But it cannot extract character names.
 *
 *  135fd497   cc               int3
 *  135fd498   77 0f            ja short 135fd4a9
 *  135fd49a   c705 a8aa1001 20>mov dword ptr ds:[0x110aaa8],0x8952d20
 *  135fd4a4  -e9 5b2b2ef0      jmp 038e0004
 *  135fd4a9   8b35 dca71001    mov esi,dword ptr ds:[0x110a7dc]
 *  135fd4af   81c6 04000000    add esi,0x4
 *  135fd4b5   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
 *  135fd4bb   81e0 ffffff3f    and eax,0x3fffffff
 *  135fd4c1   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000]   ; jichi: hook here
 *  135fd4c8   813d 68a71001 00>cmp dword ptr ds:[0x110a768],0x0
 *  135fd4d2   893d 78a71001    mov dword ptr ds:[0x110a778],edi
 *  135fd4d8   c705 aca71001 23>mov dword ptr ds:[0x110a7ac],0x23434623
 *  135fd4e2   c705 b0a71001 30>mov dword ptr ds:[0x110a7b0],0x30303030
 *  135fd4ec   8935 b4a71001    mov dword ptr ds:[0x110a7b4],esi
 *  135fd4f2   c705 b8a71001 00>mov dword ptr ds:[0x110a7b8],0x0
 *  135fd4fc   0f85 16000000    jnz 135fd518
 *  135fd502   832d c4aa1001 08 sub dword ptr ds:[0x110aac4],0x8
 *  135fd509   e9 22000000      jmp 135fd530
 *  135fd50e   01642d 95        add dword ptr ss:[ebp+ebp-0x6b],esp
 *  135fd512   08e9             or cl,ch
 *  135fd514   0b2b             or ebp,dword ptr ds:[ebx]
 *  135fd516   2e:f0:832d c4aa1>lock sub dword ptr cs:[0x110aac4],0x8    ; lock prefix
 *  135fd51f   c705 a8aa1001 40>mov dword ptr ds:[0x110aaa8],0x8952d40
 *  135fd529  -e9 f52a2ef0      jmp 038e0023
 *  135fd52e   90               nop
 *  135fd52f   cc               int3
 */
bool InsertImageepoch2PSPHook()
{
  ConsoleOutput("vnreng: Imageepoch2 PSP: enter");

  const BYTE bytes[] =  {
                                         // 135fd497   cc               int3
    0x77, 0x0f,                          // 135fd498   77 0f            ja short 135fd4a9
    0xc7,0x05, XX8,                      // 135fd49a   c705 a8aa1001 20>mov dword ptr ds:[0x110aaa8],0x8952d20
    0xe9, XX4,                           // 135fd4a4  -e9 5b2b2ef0      jmp 038e0004
    0x8b,0x35, XX4,                      // 135fd4a9   8b35 dca71001    mov esi,dword ptr ds:[0x110a7dc]
    0x81,0xc6, 0x04,0x00,0x00,0x00,      // 135fd4af   81c6 04000000    add esi,0x4
    0x8b,0x05, XX4,                      // 135fd4b5   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
    0x81,0xe0, 0xff,0xff,0xff,0x3f,      // 135fd4bb   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb8, XX4,                 // 135fd4c1   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000]   ; jichi: hook here
    0x81,0x3d, XX4, 0x00,0x00,0x00,0x00, // 135fd4c8   813d 68a71001 00>cmp dword ptr ds:[0x110a768],0x0
    0x89,0x3d, XX4,                      // 135fd4d2   893d 78a71001    mov dword ptr ds:[0x110a778],edi
    0xc7,0x05, XX8,                      // 135fd4d8   c705 aca71001 23>mov dword ptr ds:[0x110a7ac],0x23434623
    0xc7,0x05, XX8,                      // 135fd4e2   c705 b0a71001 30>mov dword ptr ds:[0x110a7b0],0x30303030
    0x89,0x35, XX4,                      // 135fd4ec   8935 b4a71001    mov dword ptr ds:[0x110a7b4],esi
    0xc7,0x05, XX4, 0x00,0x00,0x00,0x00, // 135fd4f2   c705 b8a71001 00>mov dword ptr ds:[0x110a7b8],0x0
    0x0f,0x85 //, XX4,                   // 135fd4fc   0f85 16000000    jnz 135fd518
  };
  enum { memory_offset = 3 }; // 1346d381   0fb6a8 00004007  movzx ebp,byte ptr ds:[eax+0x7400000]
  enum { hook_offset = 0x135fd4c1 - 0x135fd498 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Imageepoch2 PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT; // UTF-8, though
    hp.off = pusha_eax_off - 4;
    hp.split = pusha_ecx_off - 4;
    hp.text_fun = SpecialPSPHook;
    ConsoleOutput("vnreng: Imageepoch2 PSP: INSERT");
    NewHook(hp, L"Imageepoch2 PSP");
  }

  ConsoleOutput("vnreng: Imageepoch2 PSP: leave");
  return addr;
}

/** 7/19/2014 jichi yetigame.jp PSP engine, 0.9.8, 0.9.9
 *  Sample game: Secret Game Portable 0.9.8/0.9.9
 *
 *  Float memory addresses: two matches
 *
 *  Debug method: find current sentence, then find next sentence in the memory
 *  and add break-points. Need to patch 1 leading \u3000 space.
 *
 *  It seems that each time I ran the game, the instruction pattern would change?!
 *  == The second time I ran the game ==
 *
 *  14e49ed9   90               nop
 *  14e49eda   cc               int3
 *  14e49edb   cc               int3
 *  14e49edc   77 0f            ja short 14e49eed
 *  14e49ede   c705 a8aa1001 98>mov dword ptr ds:[0x110aaa8],0x885ff98
 *  14e49ee8  -e9 17619eee      jmp 03830004
 *  14e49eed   8b35 70a71001    mov esi,dword ptr ds:[0x110a770]
 *  14e49ef3   c1ee 1f          shr esi,0x1f
 *  14e49ef6   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
 *  14e49efc   81e0 ffffff3f    and eax,0x3fffffff
 *  14e49f02   8bb8 14deff07    mov edi,dword ptr ds:[eax+0x7ffde14]
 *  14e49f08   0335 70a71001    add esi,dword ptr ds:[0x110a770]
 *  14e49f0e   d1fe             sar esi,1
 *  14e49f10   8b05 b0a71001    mov eax,dword ptr ds:[0x110a7b0]
 *  14e49f16   81e0 ffffff3f    and eax,0x3fffffff
 *  14e49f1c   89b8 00000008    mov dword ptr ds:[eax+0x8000000],edi
 *  14e49f22   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
 *  14e49f28   81e0 ffffff3f    and eax,0x3fffffff
 *  14e49f2e   89b0 30000008    mov dword ptr ds:[eax+0x8000030],esi
 *  14e49f34   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
 *  14e49f3a   81e0 ffffff3f    and eax,0x3fffffff
 *  14e49f40   8ba8 14deff07    mov ebp,dword ptr ds:[eax+0x7ffde14]
 *  14e49f46   8bc5             mov eax,ebp
 *  14e49f48   81e0 ffffff3f    and eax,0x3fffffff
 *  14e49f4e   0fb6b0 00000008  movzx esi,byte ptr ds:[eax+0x8000000] ; jichi: hook here
 *  14e49f55   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  14e49f58   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
 *
 *  == The first time I ran the game ==
 *  There are a couple of good break-points, as follows.
 *  Only the second function is hooked.
 *
 *  138cf7a2   cc               int3
 *  138cf7a3   cc               int3
 *  138cf7a4   77 0f            ja short 138cf7b5
 *  138cf7a6   c705 a8aa1001 90>mov dword ptr ds:[0x110aaa8],0x885ff90
 *  138cf7b0  -e9 4f08a9f3      jmp 07360004
 *  138cf7b5   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
 *  138cf7bb   81e0 ffffff3f    and eax,0x3fffffff
 *  138cf7c1   8bb0 14de7f07    mov esi,dword ptr ds:[eax+0x77fde14]
 *  138cf7c7   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  138cf7cd   c705 e4a71001 98>mov dword ptr ds:[0x110a7e4],0x885ff98
 *  138cf7d7   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  138cf7de   e9 0d000000      jmp 138cf7f0
 *  138cf7e3   015c48 85        add dword ptr ds:[eax+ecx*2-0x7b],ebx
 *  138cf7e7   08e9             or cl,ch
 *  138cf7e9   36:08a9 f390cccc or byte ptr ss:[ecx+0xcccc90f3],ch
 *  138cf7f0   77 0f            ja short 138cf801
 *  138cf7f2   c705 a8aa1001 5c>mov dword ptr ds:[0x110aaa8],0x885485c
 *  138cf7fc  -e9 0308a9f3      jmp 07360004
 *  138cf801   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  138cf807   81e0 ffffff3f    and eax,0x3fffffff
 *  138cf80d   0fb6b0 00008007  movzx esi,byte ptr ds:[eax+0x7800000] ; jichi: hook here
 *  138cf814   81fe 00000000    cmp esi,0x0
 *  138cf81a   8935 74a71001    mov dword ptr ds:[0x110a774],esi
 *  138cf820   c705 80a71001 00>mov dword ptr ds:[0x110a780],0x0
 *  138cf82a   c705 84a71001 25>mov dword ptr ds:[0x110a784],0x25
 *  138cf834   c705 88a71001 4e>mov dword ptr ds:[0x110a788],0x4e
 *  138cf83e   c705 8ca71001 6e>mov dword ptr ds:[0x110a78c],0x6e
 *  138cf848   0f85 16000000    jnz 138cf864
 *  138cf84e   832d c4aa1001 06 sub dword ptr ds:[0x110aac4],0x6
 *  138cf855   e9 b6010000      jmp 138cfa10
 *  138cf85a   01bc48 8508e9bf  add dword ptr ds:[eax+ecx*2+0xbfe90885],>
 *  138cf861   07               pop es                                   ; modification of segment register
 *  138cf862   a9 f3832dc4      test eax,0xc42d83f3
 *  138cf867   aa               stos byte ptr es:[edi]
 *  138cf868   1001             adc byte ptr ds:[ecx],al
 *  138cf86a   06               push es
 *  138cf86b   e9 0c000000      jmp 138cf87c
 *  138cf870   017448 85        add dword ptr ds:[eax+ecx*2-0x7b],esi
 *  138cf874   08e9             or cl,ch
 *  138cf876   a9 07a9f390      test eax,0x90f3a907
 *  138cf87b   cc               int3
 *
 *  This function is used.
 *  138cfa46   cc               int3
 *  138cfa47   cc               int3
 *  138cfa48   77 0f            ja short 138cfa59
 *  138cfa4a   c705 a8aa1001 98>mov dword ptr ds:[0x110aaa8],0x885ff98
 *  138cfa54  -e9 ab05a9f3      jmp 07360004
 *  138cfa59   8b35 70a71001    mov esi,dword ptr ds:[0x110a770]
 *  138cfa5f   c1ee 1f          shr esi,0x1f
 *  138cfa62   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
 *  138cfa68   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfa6e   8bb8 14de7f07    mov edi,dword ptr ds:[eax+0x77fde14]
 *  138cfa74   0335 70a71001    add esi,dword ptr ds:[0x110a770]
 *  138cfa7a   d1fe             sar esi,1
 *  138cfa7c   8b05 b0a71001    mov eax,dword ptr ds:[0x110a7b0]
 *  138cfa82   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfa88   89b8 00008007    mov dword ptr ds:[eax+0x7800000],edi
 *  138cfa8e   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
 *  138cfa94   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfa9a   89b0 30008007    mov dword ptr ds:[eax+0x7800030],esi
 *  138cfaa0   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
 *  138cfaa6   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfaac   8ba8 14de7f07    mov ebp,dword ptr ds:[eax+0x77fde14]
 *  138cfab2   8bc5             mov eax,ebp
 *  138cfab4   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfaba   0fb6b0 00008007  movzx esi,byte ptr ds:[eax+0x7800000] ; jichi: hook here
 *  138cfac1   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  138cfac4   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
 *  138cfaca   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfad0   89a8 14de7f07    mov dword ptr ds:[eax+0x77fde14],ebp
 *  138cfad6   81fe 00000000    cmp esi,0x0
 *  138cfadc   892d 70a71001    mov dword ptr ds:[0x110a770],ebp
 *  138cfae2   8935 74a71001    mov dword ptr ds:[0x110a774],esi
 *  138cfae8   893d aca71001    mov dword ptr ds:[0x110a7ac],edi
 *  138cfaee   0f84 16000000    je 138cfb0a
 *  138cfaf4   832d c4aa1001 0b sub dword ptr ds:[0x110aac4],0xb
 *  138cfafb   e9 24000000      jmp 138cfb24
 *  138cfb00   01b0 ff8508e9    add dword ptr ds:[eax+0xe90885ff],esi
 *  138cfb06   1905 a9f3832d    sbb dword ptr ds:[0x2d83f3a9],eax
 *  138cfb0c   c4aa 10010be9    les ebp,fword ptr ds:[edx+0xe90b0110]    ; modification of segment register
 *  138cfb12   9a 00000001 c4ff call far ffc4:01000000                   ; far call
 *  138cfb19   8508             test dword ptr ds:[eax],ecx
 *  138cfb1b  -e9 0305a9f3      jmp 07360023
 *  138cfb20   90               nop
 *  138cfb21   cc               int3
 *  138cfb22   cc               int3
 *
 *  138cfb22   cc               int3
 *  138cfb23   cc               int3
 *  138cfb24   77 0f            ja short 138cfb35
 *  138cfb26   c705 a8aa1001 b0>mov dword ptr ds:[0x110aaa8],0x885ffb0
 *  138cfb30  -e9 cf04a9f3      jmp 07360004
 *  138cfb35   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
 *  138cfb3b   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfb41   8bb0 14de7f07    mov esi,dword ptr ds:[eax+0x77fde14]
 *  138cfb47   8bc6             mov eax,esi
 *  138cfb49   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfb4f   0fb6b8 00008007  movzx edi,byte ptr ds:[eax+0x7800000] ; jichi: hook here
 *  138cfb56   8d76 01          lea esi,dword ptr ds:[esi+0x1]
 *  138cfb59   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
 *  138cfb5f   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfb65   89b0 14de7f07    mov dword ptr ds:[eax+0x77fde14],esi
 *  138cfb6b   81ff 00000000    cmp edi,0x0
 *  138cfb71   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  138cfb77   893d 74a71001    mov dword ptr ds:[0x110a774],edi
 *  138cfb7d   0f84 16000000    je 138cfb99
 *  138cfb83   832d c4aa1001 05 sub dword ptr ds:[0x110aac4],0x5
 *  138cfb8a  ^e9 95ffffff      jmp 138cfb24
 *  138cfb8f   01b0 ff8508e9    add dword ptr ds:[eax+0xe90885ff],esi
 *  138cfb95   8a04a9           mov al,byte ptr ds:[ecx+ebp*4]
 *  138cfb98   f3:              prefix rep:                              ; superfluous prefix
 *  138cfb99   832d c4aa1001 05 sub dword ptr ds:[0x110aac4],0x5
 *  138cfba0   e9 0b000000      jmp 138cfbb0
 *  138cfba5   01c4             add esp,eax
 *  138cfba7   ff85 08e97404    inc dword ptr ss:[ebp+0x474e908]
 *  138cfbad   a9 f390770f      test eax,0xf7790f3
 *  138cfbb2   c705 a8aa1001 c4>mov dword ptr ds:[0x110aaa8],0x885ffc4
 *  138cfbbc  -e9 4304a9f3      jmp 07360004
 *  138cfbc1   f3:0f1015 6c1609>movss xmm2,dword ptr ds:[0x1009166c]
 *  138cfbc9   8b05 b0a71001    mov eax,dword ptr ds:[0x110a7b0]
 *  138cfbcf   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfbd5   8bb0 00008007    mov esi,dword ptr ds:[eax+0x7800000]
 *  138cfbdb   f3:0f101d 641609>movss xmm3,dword ptr ds:[0x10091664]
 *  138cfbe3   c7c7 00000000    mov edi,0x0
 *  138cfbe9   893d f4b12b11    mov dword ptr ds:[0x112bb1f4],edi
 *  138cfbef   8bc6             mov eax,esi
 *  138cfbf1   81e0 ffffff3f    and eax,0x3fffffff
 *  138cfbf7   0fb6a8 00008007  movzx ebp,byte ptr ds:[eax+0x7800000]  ; jichi: hook here
 *  138cfbfe   81fd 00000000    cmp ebp,0x0
 *  138cfc04   c705 70a71001 00>mov dword ptr ds:[0x110a770],0x9ac0000
 *  138cfc0e   c705 74a71001 00>mov dword ptr ds:[0x110a774],0x8890000
 *  138cfc18   892d a8a71001    mov dword ptr ds:[0x110a7a8],ebp
 *  138cfc1e   8935 aca71001    mov dword ptr ds:[0x110a7ac],esi
 *  138cfc24   c705 b4a71001 00>mov dword ptr ds:[0x110a7b4],0x8890000
 *  138cfc2e   c705 b8a71001 80>mov dword ptr ds:[0x110a7b8],0x80
 *  138cfc38   c705 bca71001 00>mov dword ptr ds:[0x110a7bc],0x0
 *  138cfc42   c705 e0a71001 00>mov dword ptr ds:[0x110a7e0],0x0
 *  138cfc4c   f3:0f111d 3ca810>movss dword ptr ds:[0x110a83c],xmm3
 *  138cfc54   f3:0f1115 40a810>movss dword ptr ds:[0x110a840],xmm2
 *  138cfc5c   0f85 16000000    jnz 138cfc78
 *  138cfc62   832d c4aa1001 0d sub dword ptr ds:[0x110aac4],0xd
 *  138cfc69   e9 32270000      jmp 138d23a0
 *  138cfc6e   0158 00          add dword ptr ds:[eax],ebx
 *  138cfc71   8608             xchg byte ptr ds:[eax],cl
 *  138cfc73  -e9 ab03a9f3      jmp 07360023
 *  138cfc78   832d c4aa1001 0d sub dword ptr ds:[0x110aac4],0xd
 *  138cfc7f   e9 0c000000      jmp 138cfc90
 *  138cfc84   01f8             add eax,edi
 *  138cfc86   ff85 08e99503    inc dword ptr ss:[ebp+0x395e908]
 *  138cfc8c   a9 f390cc77      test eax,0x77cc90f3
 *  138cfc91   0fc7             ???                                      ; unknown command
 *  138cfc93   05 a8aa1001      add eax,0x110aaa8
 *  138cfc98   f8               clc
 *  138cfc99   ff85 08e96303    inc dword ptr ss:[ebp+0x363e908]
 *  138cfc9f   a9 f38b35ac      test eax,0xac358bf3
 *  138cfca4   a7               cmps dword ptr ds:[esi],dword ptr es:[ed>
 *  138cfca5   1001             adc byte ptr ds:[ecx],al
 *  138cfca7   8b3d b4a71001    mov edi,dword ptr ds:[0x110a7b4]
 *  138cfcad   81c7 48d6ffff    add edi,-0x29b8
 *  138cfcb3   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  138cfcb9   893d 7ca71001    mov dword ptr ds:[0x110a77c],edi
 *  138cfcbf   c705 80a71001 02>mov dword ptr ds:[0x110a780],0x2
 *  138cfcc9   c705 e4a71001 08>mov dword ptr ds:[0x110a7e4],0x8860008
 *  138cfcd3   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  138cfcda  ^e9 4914f4ff      jmp 13811128
 *  138cfcdf   90               nop
 *  138cfce0   77 0f            ja short 138cfcf1
 *  138cfce2   c705 a8aa1001 74>mov dword ptr ds:[0x110aaa8],0x8844574
 *  138cfcec  -e9 1303a9f3      jmp 07360004
 *  138cfcf1   8b35 84a71001    mov esi,dword ptr ds:[0x110a784]
 *  138cfcf7   81c6 ffffffff    add esi,-0x1
 *  138cfcfd   813d 84a71001 00>cmp dword ptr ds:[0x110a784],0x0
 *  138cfd07   8935 8ca71001    mov dword ptr ds:[0x110a78c],esi
 *  138cfd0d   0f85 16000000    jnz 138cfd29
 *  138cfd13   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  138cfd1a   c705 a8aa1001 e0>mov dword ptr ds:[0x110aaa8],0x88445e0
 *  138cfd24  -e9 fa02a9f3      jmp 07360023
 *  138cfd29   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  138cfd30  ^e9 ab15f4ff      jmp 138112e0
 *  138cfd35   90               nop
 *  138cfd36   cc               int3
 *  138cfd37   cc               int3
 *
 *  13811266   cc               int3
 *  13811267   cc               int3
 *  13811268   77 0f            ja short 13811279
 *  1381126a   c705 a8aa1001 b0>mov dword ptr ds:[0x110aaa8],0x88445b0
 *  13811274  -e9 8bedb4f3      jmp 07360004
 *  13811279   8b35 8ca71001    mov esi,dword ptr ds:[0x110a78c]
 *  1381127f   8b3d 88a71001    mov edi,dword ptr ds:[0x110a788]
 *  13811285   8b2d 84a71001    mov ebp,dword ptr ds:[0x110a784]
 *  1381128b   81c5 ffffffff    add ebp,-0x1
 *  13811291   813d 84a71001 00>cmp dword ptr ds:[0x110a784],0x0
 *  1381129b   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  138112a1   893d 7ca71001    mov dword ptr ds:[0x110a77c],edi
 *  138112a7   892d 8ca71001    mov dword ptr ds:[0x110a78c],ebp
 *  138112ad   0f84 16000000    je 138112c9
 *  138112b3   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  138112ba   e9 21000000      jmp 138112e0
 *  138112bf   017c45 84        add dword ptr ss:[ebp+eax*2-0x7c],edi
 *  138112c3   08e9             or cl,ch
 *  138112c5   5a               pop edx
 *  138112c6   ed               in eax,dx                                ; i/o command
 *  138112c7   b4 f3            mov ah,0xf3
 *  138112c9   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  138112d0   c705 a8aa1001 c0>mov dword ptr ds:[0x110aaa8],0x88445c0
 *  138112da  -e9 44edb4f3      jmp 07360023
 *  138112df   90               nop
 *  138112e0   77 0f            ja short 138112f1
 *  138112e2   c705 a8aa1001 7c>mov dword ptr ds:[0x110aaa8],0x884457c
 *  138112ec  -e9 13edb4f3      jmp 07360004
 *  138112f1   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  138112f7   81e0 ffffff3f    and eax,0x3fffffff
 *  138112fd   0fb6b0 00008007  movzx esi,byte ptr ds:[eax+0x7800000] ; jichi: hook here
 *  13811304   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  1381130a   81e0 ffffff3f    and eax,0x3fffffff
 *  13811310   0fbeb8 00008007  movsx edi,byte ptr ds:[eax+0x7800000] ; jichi: hook here
 *  13811317   8bc6             mov eax,esi
 *  13811319   0fbee8           movsx ebp,al
 *  1381131c   3bef             cmp ebp,edi
 *  1381131e   893d 70a71001    mov dword ptr ds:[0x110a770],edi
 *  13811324   892d 74a71001    mov dword ptr ds:[0x110a774],ebp
 *  1381132a   8935 80a71001    mov dword ptr ds:[0x110a780],esi
 *  13811330   0f85 16000000    jnz 1381134c
 *  13811336   832d c4aa1001 05 sub dword ptr ds:[0x110aac4],0x5
 *  1381133d   e9 56110000      jmp 13812498
 *  13811342   01c8             add eax,ecx
 *  13811344   45               inc ebp
 *  13811345   8408             test byte ptr ds:[eax],cl
 *  13811347  -e9 d7ecb4f3      jmp 07360023
 *  1381134c   832d c4aa1001 05 sub dword ptr ds:[0x110aac4],0x5
 *  13811353   e9 0c000000      jmp 13811364
 *  13811358   0190 458408e9    add dword ptr ds:[eax+0xe9088445],edx
 *  1381135e   c1ec b4          shr esp,0xb4                             ; shift constant out of range 1..31
 *  13811361   f3:              prefix rep:                              ; superfluous prefix
 *  13811362   90               nop
 *  13811363   cc               int3
 *
 *  13811362   90               nop
 *  13811363   cc               int3
 *  13811364   77 0f            ja short 13811375
 *  13811366   c705 a8aa1001 90>mov dword ptr ds:[0x110aaa8],0x8844590
 *  13811370  -e9 8fecb4f3      jmp 07360004
 *  13811375   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  1381137b   81e0 ffffff3f    and eax,0x3fffffff
 *  13811381   0fb6b0 00008007  movzx esi,byte ptr ds:[eax+0x7800000] ; jichi: hook here
 *  13811388   81e6 ff000000    and esi,0xff
 *  1381138e   8b3d 80a71001    mov edi,dword ptr ds:[0x110a780]
 *  13811394   81e7 ff000000    and edi,0xff
 *  1381139a   8bc7             mov eax,edi
 *  1381139c   8bfe             mov edi,esi
 *  1381139e   2bf8             sub edi,eax
 *  138113a0   8b05 e4a71001    mov eax,dword ptr ds:[0x110a7e4]
 *  138113a6   893d 70a71001    mov dword ptr ds:[0x110a770],edi
 *  138113ac   8935 74a71001    mov dword ptr ds:[0x110a774],esi
 *  138113b2   8905 a8aa1001    mov dword ptr ds:[0x110aaa8],eax
 *  138113b8   832d c4aa1001 05 sub dword ptr ds:[0x110aac4],0x5
 *  138113bf  -e9 5fecb4f3      jmp 07360023
 *  138113c4   90               nop
 *  138113c5   cc               int3
 *  138113c6   cc               int3
 *  138113c7   cc               int3
 *
 *  138124f2   cc               int3
 *  138124f3   cc               int3
 *  138124f4   77 0f            ja short 13812505
 *  138124f6   c705 a8aa1001 d0>mov dword ptr ds:[0x110aaa8],0x88445d0
 *  13812500  -e9 ffdab4f3      jmp 07360004
 *  13812505   813d 74a71001 00>cmp dword ptr ds:[0x110a774],0x0
 *  1381250f   c705 90a71001 00>mov dword ptr ds:[0x110a790],0x0
 *  13812519   0f84 16000000    je 13812535
 *  1381251f   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  13812526   e9 21000000      jmp 1381254c
 *  1381252b   018446 8408e9ee  add dword ptr ds:[esi+eax*2+0xeee90884],>
 *  13812532   dab4f3 832dc4aa  fidiv dword ptr ds:[ebx+esi*8+0xaac42d83>
 *  13812539   1001             adc byte ptr ds:[ecx],al
 *  1381253b   02e9             add ch,cl
 *  1381253d   3302             xor eax,dword ptr ds:[edx]
 *  1381253f   0000             add byte ptr ds:[eax],al
 *  13812541   01d8             add eax,ebx
 *  13812543   45               inc ebp
 *  13812544   8408             test byte ptr ds:[eax],cl
 *  13812546  -e9 d8dab4f3      jmp 07360023
 *  1381254b   90               nop
 *  1381254c   77 0f            ja short 1381255d
 *  1381254e   c705 a8aa1001 84>mov dword ptr ds:[0x110aaa8],0x8844684
 *  13812558  -e9 a7dab4f3      jmp 07360004
 *  1381255d   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
 *  13812563   0335 8ca71001    add esi,dword ptr ds:[0x110a78c]
 *  13812569   8b3d 88a71001    mov edi,dword ptr ds:[0x110a788]
 *  1381256f   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
 *  13812572   8b2d 7ca71001    mov ebp,dword ptr ds:[0x110a77c]
 *  13812578   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  1381257b   8b15 90a71001    mov edx,dword ptr ds:[0x110a790]
 *  13812581   3b15 8ca71001    cmp edx,dword ptr ds:[0x110a78c]
 *  13812587   892d 7ca71001    mov dword ptr ds:[0x110a77c],ebp
 *  1381258d   893d 88a71001    mov dword ptr ds:[0x110a788],edi
 *  13812593   8935 94a71001    mov dword ptr ds:[0x110a794],esi
 *  13812599   0f85 16000000    jnz 138125b5
 *  1381259f   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  138125a6   c705 a8aa1001 c4>mov dword ptr ds:[0x110aaa8],0x88446c4
 *  138125b0  -e9 6edab4f3      jmp 07360023
 *  138125b5   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  138125bc   e9 0b000000      jmp 138125cc
 *  138125c1   019446 8408e958  add dword ptr ds:[esi+eax*2+0x58e90884],>
 *  138125c8   dab4f3 90770fc7  fidiv dword ptr ds:[ebx+esi*8+0xc70f7790>
 *  138125cf   05 a8aa1001      add eax,0x110aaa8
 *  138125d4   94               xchg eax,esp
 *  138125d5   46               inc esi
 *  138125d6   8408             test byte ptr ds:[eax],cl
 *  138125d8  -e9 27dab4f3      jmp 07360004
 *  138125dd   8b05 88a71001    mov eax,dword ptr ds:[0x110a788]
 *  138125e3   81e0 ffffff3f    and eax,0x3fffffff
 *  138125e9   0fb6b0 00008007  movzx esi,byte ptr ds:[eax+0x7800000] ; jichi: hook here
 *  138125f0   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  138125f6   81e0 ffffff3f    and eax,0x3fffffff
 *  138125fc   0fb6b8 00008007  movzx edi,byte ptr ds:[eax+0x7800000]
 *  13812603   8bc6             mov eax,esi
 *  13812605   0fbee8           movsx ebp,al
 *  13812608   8bc7             mov eax,edi
 *  1381260a   0fbed0           movsx edx,al
 *  1381260d   8b0d 90a71001    mov ecx,dword ptr ds:[0x110a790]
 *  13812613   8d49 01          lea ecx,dword ptr ds:[ecx+0x1]
 *  13812616   3bd5             cmp edx,ebp
 *  13812618   892d 70a71001    mov dword ptr ds:[0x110a770],ebp
 *  1381261e   8935 74a71001    mov dword ptr ds:[0x110a774],esi
 *  13812624   893d 80a71001    mov dword ptr ds:[0x110a780],edi
 *  1381262a   8915 84a71001    mov dword ptr ds:[0x110a784],edx
 *  13812630   890d 90a71001    mov dword ptr ds:[0x110a790],ecx
 *  13812636   0f84 16000000    je 13812652
 *  1381263c   832d c4aa1001 06 sub dword ptr ds:[0x110aac4],0x6
 *  13812643   e9 98d70b00      jmp 138cfde0
 *  13812648   019445 8408e9d1  add dword ptr ss:[ebp+eax*2+0xd1e90884],>
 *  1381264f   d9b4f3 832dc4aa  fstenv (28-byte) ptr ds:[ebx+esi*8+0xaac>
 *  13812656   1001             adc byte ptr ds:[ecx],al
 *  13812658   06               push es
 *  13812659   e9 0e000000      jmp 1381266c
 *  1381265e   01ac46 8408e9bb  add dword ptr ds:[esi+eax*2+0xbbe90884],>
 *  13812665   d9b4f3 90cccccc  fstenv (28-byte) ptr ds:[ebx+esi*8+0xccc>
 *  1381266c   77 0f            ja short 1381267d
 *  1381266e   c705 a8aa1001 ac>mov dword ptr ds:[0x110aaa8],0x88446ac
 *  13812678  -e9 87d9b4f3      jmp 07360004
 *  1381267d   8b35 88a71001    mov esi,dword ptr ds:[0x110a788]
 *  13812683   3b35 94a71001    cmp esi,dword ptr ds:[0x110a794]
 *  13812689   0f85 16000000    jnz 138126a5
 *  1381268f   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  13812696   e9 d9000000      jmp 13812774
 *  1381269b   01d8             add eax,ebx
 *  1381269d   45               inc ebp
 *  1381269e   8408             test byte ptr ds:[eax],cl
 *  138126a0  -e9 7ed9b4f3      jmp 07360023
 *  138126a5   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  138126ac   e9 0b000000      jmp 138126bc
 *  138126b1   01b446 8408e968  add dword ptr ds:[esi+eax*2+0x68e90884],>
 *  138126b8   d9b4f3 90770fc7  fstenv (28-byte) ptr ds:[ebx+esi*8+0xc70>
 *  138126bf   05 a8aa1001      add eax,0x110aaa8
 *  138126c4   b4 46            mov ah,0x46
 *  138126c6   8408             test byte ptr ds:[eax],cl
 *  138126c8  -e9 37d9b4f3      jmp 07360004
 *  138126cd   8b35 88a71001    mov esi,dword ptr ds:[0x110a788]
 *  138126d3   8d76 01          lea esi,dword ptr ds:[esi+0x1]
 *  138126d6   813d 84a71001 00>cmp dword ptr ds:[0x110a784],0x0
 *  138126e0   8935 88a71001    mov dword ptr ds:[0x110a788],esi
 *  138126e6   0f84 16000000    je 13812702
 *  138126ec   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  138126f3   e9 24000000      jmp 1381271c
 *  138126f8   018c46 8408e921  add dword ptr ds:[esi+eax*2+0x21e90884],>
 *  138126ff   d9b4f3 832dc4aa  fstenv (28-byte) ptr ds:[ebx+esi*8+0xaac>
 *  13812706   1001             adc byte ptr ds:[ecx],al
 *  13812708   02c7             add al,bh
 *  1381270a   05 a8aa1001      add eax,0x110aaa8
 *  1381270f   bc 468408e9      mov esp,0xe9088446
 *  13812714   0bd9             or ebx,ecx
 *  13812716   b4 f3            mov ah,0xf3
 *  13812718   90               nop
 *  13812719   cc               int3
 *  1381271a   cc               int3
 *  1381271b   cc               int3
 *
 *  This function is very similar to Imageepoch, and can have duplicate text
 *  138d1486   cc               int3
 *  138d1487   cc               int3
 *  138d1488   77 0f            ja short 138d1499
 *  138d148a   c705 a8aa1001 2c>mov dword ptr ds:[0x110aaa8],0x884452c
 *  138d1494  -e9 6beba8f3      jmp 07360004
 *  138d1499   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  138d149f   81e0 ffffff3f    and eax,0x3fffffff
 *  138d14a5   0fbeb0 00008007  movsx esi,byte ptr ds:[eax+0x7800000] ; jichi: hook here
 *  138d14ac   8b3d 7ca71001    mov edi,dword ptr ds:[0x110a77c]
 *  138d14b2   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
 *  138d14b5   8b05 74a71001    mov eax,dword ptr ds:[0x110a774]
 *  138d14bb   81e0 ffffff3f    and eax,0x3fffffff
 *  138d14c1   8bd6             mov edx,esi
 *  138d14c3   8890 00008007    mov byte ptr ds:[eax+0x7800000],dl
 *  138d14c9   8b2d 74a71001    mov ebp,dword ptr ds:[0x110a774]
 *  138d14cf   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  138d14d2   81fe 00000000    cmp esi,0x0
 *  138d14d8   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  138d14de   892d 74a71001    mov dword ptr ds:[0x110a774],ebp
 *  138d14e4   893d 7ca71001    mov dword ptr ds:[0x110a77c],edi
 *  138d14ea   0f85 16000000    jnz 138d1506
 *  138d14f0   832d c4aa1001 05 sub dword ptr ds:[0x110aac4],0x5
 *  138d14f7   e9 e8000000      jmp 138d15e4
 *  138d14fc   015445 84        add dword ptr ss:[ebp+eax*2-0x7c],edx
 *  138d1500   08e9             or cl,ch
 *  138d1502   1d eba8f383      sbb eax,0x83f3a8eb
 *  138d1507   2d c4aa1001      sub eax,0x110aac4
 *  138d150c   05 e90e0000      add eax,0xee9
 *  138d1511   0001             add byte ptr ds:[ecx],al
 *  138d1513   40               inc eax
 *  138d1514   45               inc ebp
 *  138d1515   8408             test byte ptr ds:[eax],cl
 *  138d1517  -e9 07eba8f3      jmp 07360023
 *  138d151c   90               nop
 *  138d151d   cc               int3
 *  138d151e   cc               int3
 *  138d151f   cc               int3
 */
//static void SpecialPSPHookYeti(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
//{
//  //enum { base = 0x7400000 };
//  DWORD eax = regof(eax, esp_base);
//  LPCSTR text = LPCSTR(eax + hp->user_value);
//  if (*text) {
//    *data = (DWORD)text;
//    *len = ::strlen(text); // SHIFT-JIS
//    //*split = regof(ecx, esp_base); // ecx is bad that will split text threads
//    //*split = FIXED_SPLIT_VALUE; // Similar to 5pb, it only has one thread?
//    //*split = regof(ebx, esp_base); // value of ebx is splitting
//    *split = FIXED_SPLIT_VALUE << 1; // * 2 to make it unique
//  }
//}

bool InsertYetiPSPHook()
{
  ConsoleOutput("vnreng: Yeti PSP: enter");
  const BYTE bytes[] =  {
    //0xcc,                         // 14e49edb   cc               int3
    0x77, 0x0f,                     // 14e49edc   77 0f            ja short 14e49eed
    0xc7,0x05, XX8,                 // 14e49ede   c705 a8aa1001 98>mov dword ptr ds:[0x110aaa8],0x885ff98
    0xe9, XX4,                      // 14e49ee8  -e9 17619eee      jmp 03830004
    0x8b,0x35, XX4,                 // 14e49eed   8b35 70a71001    mov esi,dword ptr ds:[0x110a770]
    0xc1,0xee, 0x1f,                // 14e49ef3   c1ee 1f          shr esi,0x1f
    0x8b,0x05, XX4,                 // 14e49ef6   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 14e49efc   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xb8, XX4,                 // 14e49f02   8bb8 14deff07    mov edi,dword ptr ds:[eax+0x7ffde14]
    0x03,0x35, XX4,                 // 14e49f08   0335 70a71001    add esi,dword ptr ds:[0x110a770]
    0xd1,0xfe,                      // 14e49f0e   d1fe             sar esi,1
    0x8b,0x05, XX4,                 // 14e49f10   8b05 b0a71001    mov eax,dword ptr ds:[0x110a7b0]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 14e49f16   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0xb8, XX4,                 // 14e49f1c   89b8 00000008    mov dword ptr ds:[eax+0x8000000],edi
    0x8b,0x05, XX4,                 // 14e49f22   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 14e49f28   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0xb0, XX4,                 // 14e49f2e   89b0 30000008    mov dword ptr ds:[eax+0x8000030],esi
    0x8b,0x05, XX4,                 // 14e49f34   8b05 b4a71001    mov eax,dword ptr ds:[0x110a7b4]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 14e49f3a   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xa8, XX4,                 // 14e49f40   8ba8 14deff07    mov ebp,dword ptr ds:[eax+0x7ffde14]
    0x8b,0xc5,                      // 14e49f46   8bc5             mov eax,ebp
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 14e49f48   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb0 //, XX4,         // 14e49f4e   0fb6b0 00000008  movzx esi,byte ptr ds:[eax+0x8000000] ; jichi: hook here
  };
  enum { memory_offset = 3 }; // 14e49f4e   0fb6b0 00000008  movzx esi,byte ptr ds:[eax+0x8000000]
  enum { hook_offset = sizeof(bytes) - memory_offset };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Yeti PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|USING_SPLIT|FIXING_SPLIT|NO_CONTEXT; // Fix the split value to merge all threads
    hp.text_fun = SpecialPSPHook;
    hp.off = pusha_eax_off - 4;
    ConsoleOutput("vnreng: Yeti PSP: INSERT");
    NewHook(hp, L"Yeti PSP");
  }

  ConsoleOutput("vnreng: Yeti PSP: leave");
  return addr;
}

/** 7/19/2014 jichi kid-game.co.jp PSP engine, 0,9.8, 0.9.9
 *  Sample game: Monochrome
 *
 *  Note: sceFontGetCharInfo, sceFontGetCharGlyphImage_Clip also works
 *
 *  Debug method: breakpoint the memory address
 *  There are two matched memory address to the current text
 *
 *  == Second run ==
 *  13973a7b   90               nop
 *  13973a7c   77 0f            ja short 13973a8d
 *  13973a7e   c705 a8aa1001 90>mov dword ptr ds:[0x110aaa8],0x885c290
 *  13973a88  -e9 77c5ecef      jmp 03840004
 *  13973a8d   8b05 90a71001    mov eax,dword ptr ds:[0x110a790]
 *  13973a93   81e0 ffffff3f    and eax,0x3fffffff
 *  13973a99   0fb6b0 00008007  movzx esi,byte ptr ds:[eax+0x7800000]
 *  13973aa0   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  13973aa6   81e0 ffffff3f    and eax,0x3fffffff
 *  13973aac   0fb6b8 00008007  movzx edi,byte ptr ds:[eax+0x7800000] ; jichi: hook here
 *  13973ab3   81fe 00000000    cmp esi,0x0
 *  13973ab9   c705 8ca71001 00>mov dword ptr ds:[0x110a78c],0x0
 *  13973ac3   893d 9ca71001    mov dword ptr ds:[0x110a79c],edi
 *  13973ac9   8935 a0a71001    mov dword ptr ds:[0x110a7a0],esi
 *  13973acf   0f85 16000000    jnz 13973aeb
 *  13973ad5   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  13973adc   c705 a8aa1001 d0>mov dword ptr ds:[0x110aaa8],0x885c2d0
 *  13973ae6  -e9 38c5ecef      jmp 03840023
 *  13973aeb   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  13973af2   e9 0d000000      jmp 13973b04
 *  13973af7   01a0 c28508e9    add dword ptr ds:[eax+0xe90885c2],esp
 *  13973afd   22c5             and al,ch
 *  13973aff   ec               in al,dx                                 ; i/o command
 *  13973b00   ef               out dx,eax                               ; i/o command
 *  13973b01   90               nop
 *  13973b02   cc               int3
 *  13973b03   cc               int3
 *
 *  == First run ==
 *  1087394a   cc               int3
 *  1087394b   cc               int3
 *  1087394c   77 0f            ja short 1087395d
 *  1087394e   c705 a8aa1001 78>mov dword ptr ds:[0x110aaa8],0x885c278
 *  10873958  -e9 a7c6bff2      jmp 03470004
 *  1087395d   8b35 80d0da12    mov esi,dword ptr ds:[0x12dad080]
 *  10873963   8bc6             mov eax,esi
 *  10873965   81e0 ffffff3f    and eax,0x3fffffff
 *  1087396b   8bb8 0000000a    mov edi,dword ptr ds:[eax+0xa000000]
 *  10873971   81ff 00000000    cmp edi,0x0
 *  10873977   c705 70a71001 00>mov dword ptr ds:[0x110a770],0x8db0000
 *  10873981   c705 74a71001 00>mov dword ptr ds:[0x110a774],0x0
 *  1087398b   893d 90a71001    mov dword ptr ds:[0x110a790],edi
 *  10873991   8935 94a71001    mov dword ptr ds:[0x110a794],esi
 *  10873997   c705 98a71001 00>mov dword ptr ds:[0x110a798],0x0
 *  108739a1   0f85 16000000    jnz 108739bd
 *  108739a7   832d c4aa1001 06 sub dword ptr ds:[0x110aac4],0x6
 *  108739ae   e9 75c20100      jmp 1088fc28
 *  108739b3   0148 c3          add dword ptr ds:[eax-0x3d],ecx
 *  108739b6   8508             test dword ptr ds:[eax],ecx
 *  108739b8  -e9 66c6bff2      jmp 03470023
 *  108739bd   832d c4aa1001 06 sub dword ptr ds:[0x110aac4],0x6
 *  108739c4   e9 0b000000      jmp 108739d4
 *  108739c9   0190 c28508e9    add dword ptr ds:[eax+0xe90885c2],edx
 *  108739cf   50               push eax
 *  108739d0   c6               ???                                      ; unknown command
 *  108739d1   bf f290770f      mov edi,0xf7790f2
 *  108739d6   c705 a8aa1001 90>mov dword ptr ds:[0x110aaa8],0x885c290
 *  108739e0  -e9 1fc6bff2      jmp 03470004
 *  108739e5   8b05 90a71001    mov eax,dword ptr ds:[0x110a790]
 *  108739eb   81e0 ffffff3f    and eax,0x3fffffff
 *  108739f1   0fb6b0 0000000a  movzx esi,byte ptr ds:[eax+0xa000000] ; jichi: hook here
 *  108739f8   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  108739fe   81e0 ffffff3f    and eax,0x3fffffff
 *  10873a04   0fb6b8 0000000a  movzx edi,byte ptr ds:[eax+0xa000000] ; jichi: hook here
 *  10873a0b   81fe 00000000    cmp esi,0x0
 *  10873a11   c705 8ca71001 00>mov dword ptr ds:[0x110a78c],0x0
 *  10873a1b   893d 9ca71001    mov dword ptr ds:[0x110a79c],edi
 *  10873a21   8935 a0a71001    mov dword ptr ds:[0x110a7a0],esi
 *  10873a27   0f85 16000000    jnz 10873a43
 *  10873a2d   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  10873a34   c705 a8aa1001 d0>mov dword ptr ds:[0x110aaa8],0x885c2d0
 *  10873a3e  -e9 e0c5bff2      jmp 03470023
 *  10873a43   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  10873a4a   e9 0d000000      jmp 10873a5c
 *  10873a4f   01a0 c28508e9    add dword ptr ds:[eax+0xe90885c2],esp
 *  10873a55   ca c5bf          retf 0xbfc5                              ; far return
 *  10873a58   f2:              prefix repne:                            ; superfluous prefix
 *  10873a59   90               nop
 *  10873a5a   cc               int3
 *  10873a5b   cc               int3
 */
static void SpecialPSPHookKid(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value);
  static LPCSTR lasttext; // Prevent reading the same address multiple times
  if (text != lasttext && *text) {
    lasttext = text;
    text = _5pbltrim(text);
    *data = (DWORD)text;
    *len = _5pbstrlen(text);
    *split = regof(ecx, esp_base);
  }
}

bool InsertKidPSPHook()
{
  ConsoleOutput("vnreng: KID PSP: enter");

  const BYTE bytes[] =  {
    //0x90,                           // 13973a7b   90               nop
    0x77, 0x0f,                     // 13973a7c   77 0f            ja short 13973a8d
    0xc7,0x05, XX8,                 // 13973a7e   c705 a8aa1001 90>mov dword ptr ds:[0x110aaa8],0x885c290
    0xe9, XX4,                      // 13973a88  -e9 77c5ecef      jmp 03840004
    0x8b,0x05, XX4,                 // 13973a8d   8b05 90a71001    mov eax,dword ptr ds:[0x110a790]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13973a93   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb0, XX4,            // 13973a99   0fb6b0 00008007  movzx esi,byte ptr ds:[eax+0x7800000]
    0x8b,0x05, XX4,                 // 13973aa0   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13973aa6   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb8, XX4,            // 13973aac   0fb6b8 00008007  movzx edi,byte ptr ds:[eax+0x7800000] ; jichi: hook here
    0x81,0xfe, 0x00,0x00,0x00,0x00  // 13973ab3   81fe 00000000    cmp esi,0x0
  };
  enum { memory_offset = 3 }; // 13973aac   0fb6b8 00008007  movzx edi,byte ptr ds:[eax+0x7800000]
  enum { hook_offset = 0x13973aac - 0x13973a7c };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: KID PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.text_fun = SpecialPSPHookKid;
    hp.type = USING_STRING|NO_CONTEXT; // no context is needed to get rid of variant retaddr

    //HookParam hp = {};
    //hp.addr = addr + hook_offset;
    //hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    //hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT; // Fix the split value to merge all threads
    //hp.off = pusha_eax_off - 4;
    //hp.split = pusha_ecx_off - 4;
    //hp.text_fun = SpecialPSPHook;

    ConsoleOutput("vnreng: KID PSP: INSERT");
    NewHook(hp, L"KID PSP");
  }

  ConsoleOutput("vnreng: KID PSP: leave");
  return addr;
}

/** 7/19/2014 jichi CYBERFRONT PSP engine, 0,9.8, 0.9.9
 *  Sample game: 想いのかけら クローストゥ (0.9.9)
 *
 *  Debug method: breakpoint the memory address
 *  There are two matched memory address to the current text
 *
 *  The second is used.
 *  The #1 is missing text.
 *
 *  #1 The text is written word by word
 *
 *  0ed8be86   90               nop
 *  0ed8be87   cc               int3
 *  0ed8be88   77 0f            ja short 0ed8be99
 *  0ed8be8a   c705 c84c1301 dc>mov dword ptr ds:[0x1134cc8],0x88151dc
 *  0ed8be94  -e9 6b41b4f4      jmp 038d0004
 *  0ed8be99   8b35 cc491301    mov esi,dword ptr ds:[0x11349cc]
 *  0ed8be9f   8d76 02          lea esi,dword ptr ds:[esi+0x2]
 *  0ed8bea2   8b3d 94491301    mov edi,dword ptr ds:[0x1134994]
 *  0ed8bea8   8b05 d0491301    mov eax,dword ptr ds:[0x11349d0]
 *  0ed8beae   81e0 ffffff3f    and eax,0x3fffffff
 *  0ed8beb4   8bd7             mov edx,edi
 *  0ed8beb6   8890 00008009    mov byte ptr ds:[eax+0x9800000],dl ; jichi: hook here, write text here
 *  0ed8bebc   8b05 c8491301    mov eax,dword ptr ds:[0x11349c8]
 *  0ed8bec2   81e0 ffffff3f    and eax,0x3fffffff
 *  0ed8bec8   0fb6a8 00008009  movzx ebp,byte ptr ds:[eax+0x9800000]
 *  0ed8becf   8b05 d0491301    mov eax,dword ptr ds:[0x11349d0]
 *  0ed8bed5   81e0 ffffff3f    and eax,0x3fffffff
 *  0ed8bedb   8bd5             mov edx,ebp
 *  0ed8bedd   8890 01008009    mov byte ptr ds:[eax+0x9800001],dl
 *  0ed8bee3   8b15 d0491301    mov edx,dword ptr ds:[0x11349d0]
 *  0ed8bee9   8d52 02          lea edx,dword ptr ds:[edx+0x2]
 *  0ed8beec   892d 90491301    mov dword ptr ds:[0x1134990],ebp
 *  0ed8bef2   8935 cc491301    mov dword ptr ds:[0x11349cc],esi
 *  0ed8bef8   8915 d0491301    mov dword ptr ds:[0x11349d0],edx
 *  0ed8befe   832d e44c1301 06 sub dword ptr ds:[0x1134ce4],0x6
 *  0ed8bf05   e9 0e000000      jmp 0ed8bf18
 *  0ed8bf0a   013451           add dword ptr ds:[ecx+edx*2],esi
 *  0ed8bf0d   8108 e90f41b4    or dword ptr ds:[eax],0xb4410fe9
 *  0ed8bf13   f4               hlt                                      ; privileged command
 *  0ed8bf14   90               nop
 *  0ed8bf15   cc               int3
 *
 *  #2 The text is read
 *
 *  Issue: the text is read multiple times.
 *  Only esp > 0xfff is kept.
 *
 *  0ed8cf13   90               nop
 *  0ed8cf14   77 0f            ja short 0ed8cf25
 *  0ed8cf16   c705 c84c1301 b8>mov dword ptr ds:[0x1134cc8],0x888d1b8
 *  0ed8cf20  -e9 df30b4f4      jmp 038d0004
 *  0ed8cf25   8b05 98491301    mov eax,dword ptr ds:[0x1134998]
 *  0ed8cf2b   81e0 ffffff3f    and eax,0x3fffffff
 *  0ed8cf31   0fb6b0 00008009  movzx esi,byte ptr ds:[eax+0x9800000] ; jichi: hook here
 *  0ed8cf38   81fe 00000000    cmp esi,0x0
 *  0ed8cf3e   8935 90491301    mov dword ptr ds:[0x1134990],esi
 *  0ed8cf44   0f85 2f000000    jnz 0ed8cf79
 *  0ed8cf4a   8b05 9c491301    mov eax,dword ptr ds:[0x113499c]
 *  0ed8cf50   81e0 ffffff3f    and eax,0x3fffffff
 *  0ed8cf56   0fbeb0 00008009  movsx esi,byte ptr ds:[eax+0x9800000]
 *  0ed8cf5d   8935 90491301    mov dword ptr ds:[0x1134990],esi
 *  0ed8cf63   832d e44c1301 03 sub dword ptr ds:[0x1134ce4],0x3
 *  0ed8cf6a   c705 c84c1301 18>mov dword ptr ds:[0x1134cc8],0x888d218
 *  0ed8cf74  -e9 aa30b4f4      jmp 038d0023
 *  0ed8cf79   832d e44c1301 03 sub dword ptr ds:[0x1134ce4],0x3
 *  0ed8cf80   e9 0b000000      jmp 0ed8cf90
 *  0ed8cf85   01c4             add esp,eax
 *  0ed8cf87   d188 08e99430    ror dword ptr ds:[eax+0x3094e908],1
 *  0ed8cf8d   b4 f4            mov ah,0xf4
 *  0ed8cf8f   90               nop
 */

static void SpecialPSPHookCyberfront(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD splitvalue = regof(edi, esp_base);
  if (splitvalue < 0x0fff)
    return;
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value);
  if (*text) {
    *data = (DWORD)text;
    *len = ::strlen(text);
    *split = splitvalue;
  }
}
bool InsertCyberfrontPSPHook()
{
  ConsoleOutput("vnreng: CYBERFRONT PSP: enter");

  const BYTE bytes[] =  {
                                    // 0ed8cf13   90               nop
    0x77, 0x0f,                     // 0ed8cf14   77 0f            ja short 0ed8cf25
    0xc7,0x05, XX8,                 // 0ed8cf16   c705 c84c1301 b8>mov dword ptr ds:[0x1134cc8],0x888d1b8
    0xe9, XX4,                      // 0ed8cf20  -e9 df30b4f4      jmp 038d0004
    0x8b,0x05, XX4,                 // 0ed8cf25   8b05 98491301    mov eax,dword ptr ds:[0x1134998]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 0ed8cf2b   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb0, XX4,            // 0ed8cf31   0fb6b0 00008009  movzx esi,byte ptr ds:[eax+0x9800000] ; jichi: hook here
    0x81,0xfe, 0x00,0x00,0x00,0x00, // 0ed8cf38   81fe 00000000    cmp esi,0x0
    0x89,0x35, XX4,                 // 0ed8cf3e   8935 90491301    mov dword ptr ds:[0x1134990],esi
    0x0f,0x85, 0x2f,0x00,0x00,0x00, // 0ed8cf44   0f85 2f000000    jnz 0ed8cf79
    0x8b,0x05, XX4,                 // 0ed8cf4a   8b05 9c491301    mov eax,dword ptr ds:[0x113499c]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 0ed8cf50   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xbe,0xb0, XX4,            // 0ed8cf56   0fbeb0 00008009  movsx esi,byte ptr ds:[eax+0x9800000]
    0x89,0x35, XX4,                 // 0ed8cf5d   8935 90491301    mov dword ptr ds:[0x1134990],esi
    0x83,0x2d, XX4, 0x03,           // 0ed8cf63   832d e44c1301 03 sub dword ptr ds:[0x1134ce4],0x3
    0xc7,0x05 //, XX8               // 0ed8cf6a   c705 c84c1301 18>mov dword ptr ds:[0x1134cc8],0x888d218
  };
  enum { memory_offset = 3 }; // 13909a51   8890 00008007    mov byte ptr ds:[eax+0x7800000],dl
  enum { hook_offset = 0x0ed8cf31 - 0x0ed8cf14 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  //ITH_GROWL_DWORD(addr);
  if (!addr)
    ConsoleOutput("vnreng: CYBERFRONT PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT;
    //hp.off = pusha_eax_off - 4;
    //hp.split = pusha_edi_off - 4;
    hp.text_fun = SpecialPSPHookCyberfront;
    ConsoleOutput("vnreng: CYBERFRONT PSP: INSERT");
    NewHook(hp, L"CYBERFRONT PSP");
  }

  ConsoleOutput("vnreng: CYBERFRONT PSP: leave");
  return addr;
}

/** 7/19/2014 jichi Alternative Yeti PSP engine, 0.9.8, 0.9.9
 *  Sample game: Never 7, 0.9.8 & 0.9.9
 *  Sample game: ひまわり
 *
 *  Do not work on 0.9.9 Ever17 (7/27/2014)
 *
 *
 *  This hook does not work for 12River.
 *  However, sceFont functions work.
 *
 *  Memory address is FIXED.
 *  Debug method: breakpoint the memory address
 *  There are two matched memory address to the current text
 *
 *  There are several functions. The first one is used.
 *
 *  The text also has 5pb-like garbage, but it is difficult to trim.
 *
 *  PPSSPP 0.9.8:
 *
 *  14289802   cc               int3
 *  14289803   cc               int3
 *  14289804   77 0f            ja short 14289815
 *  14289806   c705 a8aa1001 58>mov dword ptr ds:[0x110aaa8],0x881ab58
 *  14289810  -e9 ef6767ef      jmp 03900004
 *  14289815   8b35 74a71001    mov esi,dword ptr ds:[0x110a774]
 *  1428981b   0335 78a71001    add esi,dword ptr ds:[0x110a778]
 *  14289821   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
 *  14289827   81e0 ffffff3f    and eax,0x3fffffff
 *  1428982d   8bb8 28004007    mov edi,dword ptr ds:[eax+0x7400028]
 *  14289833   8bc6             mov eax,esi
 *  14289835   81e0 ffffff3f    and eax,0x3fffffff
 *  1428983b   8bd7             mov edx,edi
 *  1428983d   8890 10044007    mov byte ptr ds:[eax+0x7400410],dl
 *  14289843   8b05 b0a71001    mov eax,dword ptr ds:[0x110a7b0]
 *  14289849   81e0 ffffff3f    and eax,0x3fffffff
 *  1428984f   8bb8 84004007    mov edi,dword ptr ds:[eax+0x7400084]
 *  14289855   8b05 aca71001    mov eax,dword ptr ds:[0x110a7ac]
 *  1428985b   81e0 ffffff3f    and eax,0x3fffffff
 *  14289861   0fb6a8 00004007  movzx ebp,byte ptr ds:[eax+0x7400000] ; jichi: hook here
 *  14289868   81ff 00000000    cmp edi,0x0
 *  1428986e   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  14289874   893d 74a71001    mov dword ptr ds:[0x110a774],edi
 *  1428987a   892d 78a71001    mov dword ptr ds:[0x110a778],ebp
 *  14289880   0f85 16000000    jnz 1428989c
 *  14289886   832d c4aa1001 06 sub dword ptr ds:[0x110aac4],0x6
 *  1428988d   c705 a8aa1001 ac>mov dword ptr ds:[0x110aaa8],0x881aeac
 *  14289897  -e9 876767ef      jmp 03900023
 *  1428989c   832d c4aa1001 06 sub dword ptr ds:[0x110aac4],0x6
 *  142898a3   e9 0c000000      jmp 142898b4
 *  142898a8   0170 ab          add dword ptr ds:[eax-0x55],esi
 *  142898ab   8108 e9716767    or dword ptr ds:[eax],0x676771e9
 *  142898b1   ef               out dx,eax                               ; i/o command
 *  142898b2   90               nop
 *
 *  142878ed   cc               int3
 *  142878ee   cc               int3
 *  142878ef   cc               int3
 *  142878f0   77 0f            ja short 14287901
 *  142878f2   c705 a8aa1001 44>mov dword ptr ds:[0x110aaa8],0x8811e44
 *  142878fc  -e9 038767ef      jmp 03900004
 *  14287901   8b35 70a71001    mov esi,dword ptr ds:[0x110a770]
 *  14287907   8b05 b0a71001    mov eax,dword ptr ds:[0x110a7b0]
 *  1428790d   81e0 ffffff3f    and eax,0x3fffffff
 *  14287913   8bd6             mov edx,esi
 *  14287915   8890 00004007    mov byte ptr ds:[eax+0x7400000],dl ; jichi: hook here
 *  1428791b   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
 *  14287921   81e0 ffffff3f    and eax,0x3fffffff
 *  14287927   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000]
 *  1428792e   8b2d aca71001    mov ebp,dword ptr ds:[0x110a7ac]
 *  14287934   81c5 02000000    add ebp,0x2
 *  1428793a   8bd5             mov edx,ebp
 *  1428793c   8915 aca71001    mov dword ptr ds:[0x110a7ac],edx
 *  14287942   8b05 b0a71001    mov eax,dword ptr ds:[0x110a7b0]
 *  14287948   81e0 ffffff3f    and eax,0x3fffffff
 *  1428794e   8bd7             mov edx,edi
 *  14287950   8890 01004007    mov byte ptr ds:[eax+0x7400001],dl
 *  14287956   8b15 b0a71001    mov edx,dword ptr ds:[0x110a7b0]
 *  1428795c   8d52 02          lea edx,dword ptr ds:[edx+0x2]
 *  1428795f   893d 74a71001    mov dword ptr ds:[0x110a774],edi
 *  14287965   892d a8a71001    mov dword ptr ds:[0x110a7a8],ebp
 *  1428796b   8915 b0a71001    mov dword ptr ds:[0x110a7b0],edx
 *  14287971   832d c4aa1001 07 sub dword ptr ds:[0x110aac4],0x7
 *  14287978   e9 0b000000      jmp 14287988
 *  1428797d   01a8 1d8108e9    add dword ptr ds:[eax+0xe908811d],ebp
 *  14287983   9c               pushfd
 *  14287984   8667 ef          xchg byte ptr ds:[edi-0x11],ah
 *  14287987   90               nop
 *
 *  14289a2a   90               nop
 *  14289a2b   cc               int3
 *  14289a2c   77 0f            ja short 14289a3d
 *  14289a2e   c705 a8aa1001 b4>mov dword ptr ds:[0x110aaa8],0x881abb4
 *  14289a38  -e9 c76567ef      jmp 03900004
 *  14289a3d   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
 *  14289a43   81e0 ffffff3f    and eax,0x3fffffff
 *  14289a49   8bb0 18004007    mov esi,dword ptr ds:[eax+0x7400018]
 *  14289a4f   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
 *  14289a55   81e0 ffffff3f    and eax,0x3fffffff
 *  14289a5b   8bb8 24004007    mov edi,dword ptr ds:[eax+0x7400024]
 *  14289a61   8b2d 70a71001    mov ebp,dword ptr ds:[0x110a770]
 *  14289a67   03ee             add ebp,esi
 *  14289a69   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
 *  14289a6f   81e0 ffffff3f    and eax,0x3fffffff
 *  14289a75   8bb0 20004007    mov esi,dword ptr ds:[eax+0x7400020]
 *  14289a7b   8bc5             mov eax,ebp
 *  14289a7d   81e0 ffffff3f    and eax,0x3fffffff
 *  14289a83   66:89b8 c2034007 mov word ptr ds:[eax+0x74003c2],di
 *  14289a8a   8bc5             mov eax,ebp
 *  14289a8c   81e0 ffffff3f    and eax,0x3fffffff
 *  14289a92   66:89b0 c0034007 mov word ptr ds:[eax+0x74003c0],si
 *  14289a99   8b05 aca71001    mov eax,dword ptr ds:[0x110a7ac]
 *  14289a9f   81e0 ffffff3f    and eax,0x3fffffff
 *  14289aa5   0fb6b0 00004007  movzx esi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
 *  14289aac   81e6 ff000000    and esi,0xff
 *  14289ab2   892d 70a71001    mov dword ptr ds:[0x110a770],ebp
 *  14289ab8   893d 74a71001    mov dword ptr ds:[0x110a774],edi
 *  14289abe   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  14289ac4   c705 e4a71001 d8>mov dword ptr ds:[0x110a7e4],0x881abd8
 *  14289ace   832d c4aa1001 09 sub dword ptr ds:[0x110aac4],0x9
 *  14289ad5  ^e9 d6c6f8ff      jmp 142161b0
 *  14289ada   90               nop
 *
 *  14289adb   cc               int3
 *  14289adc   77 0f            ja short 14289aed
 *  14289ade   c705 a8aa1001 d8>mov dword ptr ds:[0x110aaa8],0x881abd8
 *  14289ae8  -e9 176567ef      jmp 03900004
 *  14289aed   813d 70a71001 00>cmp dword ptr ds:[0x110a770],0x0
 *  14289af7   0f85 2f000000    jnz 14289b2c
 *  14289afd   8b05 aca71001    mov eax,dword ptr ds:[0x110a7ac]
 *  14289b03   81e0 ffffff3f    and eax,0x3fffffff
 *  14289b09   0fb6b0 00004007  movzx esi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
 *  14289b10   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  14289b16   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  14289b1d   e9 22000000      jmp 14289b44
 *  14289b22   0110             add dword ptr ds:[eax],edx
 *  14289b24   af               scas dword ptr es:[edi]
 *  14289b25   8108 e9f76467    or dword ptr ds:[eax],0x6764f7e9
 *  14289b2b   ef               out dx,eax                               ; i/o command
 *  14289b2c   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  14289b33   c705 a8aa1001 e0>mov dword ptr ds:[0x110aaa8],0x881abe0
 *  14289b3d  -e9 e16467ef      jmp 03900023
 *
 *  PPSSPP 0.9.9 (7/27/2014)
 *
 *  0ed85942   cc               int3
 *  0ed85943   cc               int3
 *  0ed85944   77 0f            ja short 0ed85955
 *  0ed85946   c705 c84c1301 58>mov dword ptr ds:[0x1134cc8],0x881ab58
 *  0ed85950  -e9 afa6aef4      jmp 03870004
 *  0ed85955   8b35 94491301    mov esi,dword ptr ds:[0x1134994]
 *  0ed8595b   0335 98491301    add esi,dword ptr ds:[0x1134998]
 *  0ed85961   8b05 fc491301    mov eax,dword ptr ds:[0x11349fc]
 *  0ed85967   81e0 ffffff3f    and eax,0x3fffffff
 *  0ed8596d   8bb8 28008009    mov edi,dword ptr ds:[eax+0x9800028]
 *  0ed85973   8bc6             mov eax,esi
 *  0ed85975   81e0 ffffff3f    and eax,0x3fffffff
 *  0ed8597b   8bd7             mov edx,edi
 *  0ed8597d   8890 10048009    mov byte ptr ds:[eax+0x9800410],dl
 *  0ed85983   8b05 d0491301    mov eax,dword ptr ds:[0x11349d0]
 *  0ed85989   81e0 ffffff3f    and eax,0x3fffffff
 *  0ed8598f   8bb8 84008009    mov edi,dword ptr ds:[eax+0x9800084]
 *  0ed85995   8b05 cc491301    mov eax,dword ptr ds:[0x11349cc]
 *  0ed8599b   81e0 ffffff3f    and eax,0x3fffffff
 *  0ed859a1   0fb6a8 00008009  movzx ebp,byte ptr ds:[eax+0x9800000] ; jichi: hook here
 *  0ed859a8   81ff 00000000    cmp edi,0x0
 *  0ed859ae   8935 90491301    mov dword ptr ds:[0x1134990],esi
 *  0ed859b4   893d 94491301    mov dword ptr ds:[0x1134994],edi
 *  0ed859ba   892d 98491301    mov dword ptr ds:[0x1134998],ebp
 *  0ed859c0   0f85 16000000    jnz 0ed859dc
 *  0ed859c6   832d e44c1301 06 sub dword ptr ds:[0x1134ce4],0x6
 *  0ed859cd   c705 c84c1301 ac>mov dword ptr ds:[0x1134cc8],0x881aeac
 *  0ed859d7  -e9 47a6aef4      jmp 03870023
 *  0ed859dc   832d e44c1301 06 sub dword ptr ds:[0x1134ce4],0x6
 *  0ed859e3   e9 0c000000      jmp 0ed859f4
 *  0ed859e8   0170 ab          add dword ptr ds:[eax-0x55],esi
 *  0ed859eb   8108 e931a6ae    or dword ptr ds:[eax],0xaea631e9
 *  0ed859f1   f4               hlt                                      ; privileged command
 *  0ed859f2   90               nop
 */
// TODO: Is reverse_strlen a better choice?
static void SpecialPSPHookYeti2(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value);
  if (BYTE c = *(BYTE *)text) {
    *data = (DWORD)text;
    //*len = text[1] ? 2 : 1;
    *len = ::LeadByteTable[c];

    *split = regof(edx, esp_base);
    //DWORD ecx = regof(ecx, esp_base);
    //*split = ecx ? (FIXED_SPLIT_VALUE << 1) : 0; // << 1 to be unique, non-zero ecx is what I want
  }
}

bool InsertYeti2PSPHook()
{
  ConsoleOutput("vnreng: Yeti2 PSP: enter");

  const BYTE bytes[] =  {
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 14289827   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xb8, XX4,                 // 1428982d   8bb8 28004007    mov edi,dword ptr ds:[eax+0x7400028]
    0x8b,0xc6,                      // 14289833   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 14289835   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xd7,                      // 1428983b   8bd7             mov edx,edi
    0x88,0x90, XX4,                 // 1428983d   8890 10044007    mov byte ptr ds:[eax+0x7400410],dl
    0x8b,0x05, XX4,                 // 14289843   8b05 b0a71001    mov eax,dword ptr ds:[0x110a7b0]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 14289849   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xb8, XX4,                 // 1428984f   8bb8 84004007    mov edi,dword ptr ds:[eax+0x7400084]
    0x8b,0x05, XX4,                 // 14289855   8b05 aca71001    mov eax,dword ptr ds:[0x110a7ac]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1428985b   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xa8 //, XX4          // 14289861   0fb6a8 00004007  movzx ebp,byte ptr ds:[eax+0x7400000] ; jichi: hook here
                                    // 14289b10   8935 70a71001    mov dword ptr ds:[0x110a770],esi
                                    // 14289b16   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
  };
  enum { memory_offset = 3 };
  enum { hook_offset = sizeof(bytes) - memory_offset };
  //enum { hook_offset = sizeof(bytes) + 4 }; // point to next statement after ebp is assigned

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Yeti2 PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|NO_CONTEXT;
    //hp.off = pusha_eax_off - 4;
    //hp.split = pusha_ecx_off - 4; // this would split scenario thread
    //hp.split = hp.off; // directly use text address to split
    hp.text_fun = SpecialPSPHookYeti2;
    ConsoleOutput("vnreng: Yeti2 PSP: INSERT");
    NewHook(hp, L"Yeti2 PSP");
  }

  ConsoleOutput("vnreng: Yeti2 PSP: leave");
  return addr;
}

/** 7/22/2014 jichi BANDAI PSP engine, 0.9.8 only
 *  Replaced by Otomate PPSSPP on 0.9.9.
 *  Sample game: School Rumble PSP 姉さん事件です (SHIFT-JIS)
 *  See: http://sakuradite.com/topic/333
 *
 *  Sample game: 密室のサクリファイス work on 0.9.8, not 0.9.9
 *
 *
 *  Sample game: Shining Hearts (UTF-8)
 *  See: http://sakuradite.com/topic/346
 *
 *  The encoding could be either UTF-8 or SHIFT-JIS
 *
 *  Debug method: breakpoint the memory address
 *  There are two matched memory address to the current text
 *
 *  Only one function is accessing the text address.
 *
 *  Character name:
 *
 *  1346c122   cc               int3
 *  1346c123   cc               int3
 *  1346c124   77 0f            ja short 1346c135
 *  1346c126   c705 a8aa1001 a4>mov dword ptr ds:[0x110aaa8],0x882f2a4
 *  1346c130  -e9 cf3e2cf0      jmp 03730004
 *  1346c135   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
 *  1346c13b   81e0 ffffff3f    and eax,0x3fffffff
 *  1346c141   8bb0 14004007    mov esi,dword ptr ds:[eax+0x7400014]
 *  1346c147   8b3d 70a71001    mov edi,dword ptr ds:[0x110a770]
 *  1346c14d   c1e7 02          shl edi,0x2
 *  1346c150   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
 *  1346c156   81e0 ffffff3f    and eax,0x3fffffff
 *  1346c15c   8ba8 18004007    mov ebp,dword ptr ds:[eax+0x7400018]
 *  1346c162   03fe             add edi,esi
 *  1346c164   8bc7             mov eax,edi
 *  1346c166   81e0 ffffff3f    and eax,0x3fffffff
 *  1346c16c   0fb790 02004007  movzx edx,word ptr ds:[eax+0x7400002]
 *  1346c173   8bc2             mov eax,edx
 *  1346c175   8bd5             mov edx,ebp
 *  1346c177   03d0             add edx,eax
 *  1346c179   8bc2             mov eax,edx
 *  1346c17b   81e0 ffffff3f    and eax,0x3fffffff
 *  1346c181   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
 *  1346c188   8bcf             mov ecx,edi
 *  1346c18a   81e7 ff000000    and edi,0xff
 *  1346c190   8935 74a71001    mov dword ptr ds:[0x110a774],esi
 *  1346c196   8b35 b8a71001    mov esi,dword ptr ds:[0x110a7b8]
 *  1346c19c   81c6 bc82ffff    add esi,0xffff82bc
 *  1346c1a2   81ff 00000000    cmp edi,0x0
 *  1346c1a8   893d 70a71001    mov dword ptr ds:[0x110a770],edi
 *  1346c1ae   8915 78a71001    mov dword ptr ds:[0x110a778],edx
 *  1346c1b4   892d 7ca71001    mov dword ptr ds:[0x110a77c],ebp
 *  1346c1ba   890d 80a71001    mov dword ptr ds:[0x110a780],ecx
 *  1346c1c0   8935 84a71001    mov dword ptr ds:[0x110a784],esi
 *  1346c1c6   0f85 16000000    jnz 1346c1e2
 *  1346c1cc   832d c4aa1001 0b sub dword ptr ds:[0x110aac4],0xb
 *  1346c1d3   e9 3c050000      jmp 1346c714
 *  1346c1d8   014cf3 82        add dword ptr ds:[ebx+esi*8-0x7e],ecx
 *  1346c1dc   08e9             or cl,ch
 *  1346c1de   41               inc ecx
 *  1346c1df   3e:2c f0         sub al,0xf0                              ; superfluous prefix
 *  1346c1e2   832d c4aa1001 0b sub dword ptr ds:[0x110aac4],0xb
 *  1346c1e9   e9 0e000000      jmp 1346c1fc
 *  1346c1ee   01d0             add eax,edx
 *  1346c1f0   f2:              prefix repne:                            ; superfluous prefix
 *  1346c1f1   8208 e9          or byte ptr ds:[eax],0xffffffe9
 *  1346c1f4   2b3e             sub edi,dword ptr ds:[esi]
 *  1346c1f6   2c f0            sub al,0xf0
 *  1346c1f8   90               nop
 *  1346c1f9   cc               int3
 *  1346c1fa   cc               int3
 *  1346c1fb   cc               int3
 *
 *  Scenario:
 *
 *  1340055d   cc               int3
 *  1340055e   cc               int3
 *  1340055f   cc               int3
 *  13400560   77 0f            ja short 13400571
 *  13400562   c705 a8aa1001 cc>mov dword ptr ds:[0x110aaa8],0x883decc
 *  1340056c  -e9 93fa54f0      jmp 03950004
 *  13400571   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
 *  13400577   81c6 01000000    add esi,0x1
 *  1340057d   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  13400583   81e0 ffffff3f    and eax,0x3fffffff
 *  13400589   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
 *  13400590   8b2d 78a71001    mov ebp,dword ptr ds:[0x110a778]
 *  13400596   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  13400599   81ff 00000000    cmp edi,0x0
 *  1340059f   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  134005a5   893d 74a71001    mov dword ptr ds:[0x110a774],edi
 *  134005ab   892d 78a71001    mov dword ptr ds:[0x110a778],ebp
 *  134005b1   0f84 16000000    je 134005cd
 *  134005b7   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  134005be   e9 21000000      jmp 134005e4
 *  134005c3   01d0             add eax,edx
 *  134005c5   de83 08e956fa    fiadd word ptr ds:[ebx+0xfa56e908]
 *  134005cb   54               push esp
 *  134005cc   f0:832d c4aa1001>lock sub dword ptr ds:[0x110aac4],0x4    ; lock prefix
 *  134005d4   e9 7f000000      jmp 13400658
 *  134005d9   01dc             add esp,ebx
 *  134005db   de83 08e940fa    fiadd word ptr ds:[ebx+0xfa40e908]
 *  134005e1   54               push esp
 *  134005e2   f0:90            lock nop                                 ; lock prefix is not allowed
 *  134005e4   77 0f            ja short 134005f5
 *  134005e6   c705 a8aa1001 d0>mov dword ptr ds:[0x110aaa8],0x883ded0
 *  134005f0  -e9 0ffa54f0      jmp 03950004
 *  134005f5   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  134005fb   81e0 ffffff3f    and eax,0x3fffffff
 *  13400601   0fb6b0 00004007  movzx esi,byte ptr ds:[eax+0x7400000]
 *  13400608   8b3d 78a71001    mov edi,dword ptr ds:[0x110a778]
 *  1340060e   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
 *  13400611   81fe 00000000    cmp esi,0x0
 *  13400617   8935 74a71001    mov dword ptr ds:[0x110a774],esi
 *  1340061d   893d 78a71001    mov dword ptr ds:[0x110a778],edi
 *  13400623   0f84 16000000    je 1340063f
 *  13400629   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  13400630  ^e9 afffffff      jmp 134005e4
 *  13400635   01d0             add eax,edx
 *  13400637   de83 08e9e4f9    fiadd word ptr ds:[ebx+0xf9e4e908]
 *  1340063d   54               push esp
 *  1340063e   f0:832d c4aa1001>lock sub dword ptr ds:[0x110aac4],0x3    ; lock prefix
 *  13400646   e9 0d000000      jmp 13400658
 *  1340064b   01dc             add esp,ebx
 *  1340064d   de83 08e9cef9    fiadd word ptr ds:[ebx+0xf9cee908]
 *  13400653   54               push esp
 *  13400654   f0:90            lock nop                                 ; lock prefix is not allowed
 *  13400656   cc               int3
 *  13400657   cc               int3
 */
bool InsertBandaiNamePSPHook()
{
  ConsoleOutput("vnreng: BANDAI Name PSP: enter");

  const BYTE bytes[] =  {
    //0xcc,                         // 1346c122   cc               int3
    //0xcc,                         // 1346c123   cc               int3
    0x77, 0x0f,                     // 1346c124   77 0f            ja short 1346c135
    0xc7,0x05, XX8,                 // 1346c126   c705 a8aa1001 a4>mov dword ptr ds:[0x110aaa8],0x882f2a4
    0xe9, XX4,                      // 1346c130  -e9 cf3e2cf0      jmp 03730004
    0x8b,0x05, XX4,                 // 1346c135   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1346c13b   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xb0, XX4,                 // 1346c141   8bb0 14004007    mov esi,dword ptr ds:[eax+0x7400014]
    0x8b,0x3d, XX4,                 // 1346c147   8b3d 70a71001    mov edi,dword ptr ds:[0x110a770]
    0xc1,0xe7, 0x02,                // 1346c14d   c1e7 02          shl edi,0x2
    0x8b,0x05, XX4,                 // 1346c150   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1346c156   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xa8, XX4,                 // 1346c15c   8ba8 18004007    mov ebp,dword ptr ds:[eax+0x7400018]
    0x03,0xfe,                      // 1346c162   03fe             add edi,esi
    0x8b,0xc7,                      // 1346c164   8bc7             mov eax,edi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1346c166   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb7,0x90, XX4,            // 1346c16c   0fb790 02004007  movzx edx,word ptr ds:[eax+0x7400002]
    0x8b,0xc2,                      // 1346c173   8bc2             mov eax,edx
    0x8b,0xd5,                      // 1346c175   8bd5             mov edx,ebp
    0x03,0xd0,                      // 1346c177   03d0             add edx,eax
    0x8b,0xc2,                      // 1346c179   8bc2             mov eax,edx
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1346c17b   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb8 //, XX4          // 1346c181   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
  };
  enum { memory_offset = 3 };  // 1346c181   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000]
  enum { hook_offset = sizeof(bytes) - memory_offset };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: BANDAI Name PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT;
    hp.off = pusha_eax_off - 4;
    hp.split = pusha_ebx_off - 4;
    hp.text_fun = SpecialPSPHook;
    ConsoleOutput("vnreng: BANDAI Name PSP: INSERT");
    NewHook(hp, L"BANDAI Name PSP");
  }

  ConsoleOutput("vnreng: BANDAI Name PSP: leave");
  return addr;
}

namespace { // unnamed

inline bool _bandaigarbage_ch(char c)
{
  return c == ' ' || c == '/' || c == '#' || c == '.' || c == ':'
      || c >= '0' && c <= '9'
      || c >= 'A' && c <= 'z'; // also ignore ASCII 91-96: [ \ ] ^ _ `
}

// Remove trailing /L/P or #n garbage
size_t _bandaistrlen(LPCSTR text)
{
  size_t len = ::strlen(text);
  size_t ret = len;
  while (len && _bandaigarbage_ch(text[len - 1])) {
    len--;
    if (text[len] == '/' || text[len] == '#') // in case trim UTF-8 trailing bytes
      ret = len;
  }
  return ret;
}

// Trim leading garbage
LPCSTR _bandailtrim(LPCSTR p)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  if (p)
    for (int count = 0; (*p) && count < MAX_LENGTH; count++, p++)
      if (!_bandaigarbage_ch(*p))
        return p;
  return nullptr;
}
} // unnamed namespae

static void SpecialPSPHookBandai(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value);

  if (*text) {
    //lasttext = text;
    text = _bandailtrim(text);
    *data = (DWORD)text;
    *len = _bandaistrlen(text);

    // Issue: The split value will create lots of threads for Shining Hearts
    //*split = regof(ecx, esp_base); // works for Shool Rumble, but mix character name for Shining Hearts
    *split = regof(edi, esp_base); // works for Shining Hearts to split character name
  }
}

// 7/22/2014 jichi: This engine works for multiple game?
// It is also observed in Broccoli game うたの☆プリンスさまっ.
bool InsertBandaiPSPHook()
{
  ConsoleOutput("vnreng: BANDAI PSP: enter");

  const BYTE bytes[] =  {
    0x77, 0x0f,                     // 13400560   77 0f            ja short 13400571
    0xc7,0x05, XX8,                 // 13400562   c705 a8aa1001 cc>mov dword ptr ds:[0x110aaa8],0x883decc
    0xe9, XX4,                      // 1340056c  -e9 93fa54f0      jmp 03950004
    0x8b,0x35, XX4,                 // 13400571   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
    0x81,0xc6, 0x01,0x00,0x00,0x00, // 13400577   81c6 01000000    add esi,0x1
    0x8b,0x05, XX4,                 // 1340057d   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13400583   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb8, XX4,            // 13400589   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
    0x8b,0x2d, XX4,                 // 13400590   8b2d 78a71001    mov ebp,dword ptr ds:[0x110a778]
    0x8d,0x6d, 0x01,                // 13400596   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
    0x81,0xff, 0x00,0x00,0x00,0x00  // 13400599   81ff 00000000    cmp edi,0x0
  };
  enum { memory_offset = 3 };  // 13400589   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000]
  enum { hook_offset = 0x13400589 - 0x13400560 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: BANDAI PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT;
    //hp.off = pusha_eax_off - 4;
    //hp.split = pusha_ecx_off - 4;
    hp.text_fun = SpecialPSPHookBandai;
    ConsoleOutput("vnreng: BANDAI PSP: INSERT");
    NewHook(hp, L"BANDAI PSP");
  }

  ConsoleOutput("vnreng: BANDAI PSP: leave");
  return addr;
}

/** 7/22/2014 jichi: Nippon1 PSP engine, 0.9.8 only
 *  Sample game: うたの☆プリンスさまっ♪  (0.9.8 only)
 *
 *  Memory address is FIXED.
 *  Debug method: breakpoint the precomputed address
 *
 *  The data is in (WORD)bp instead of eax.
 *  bp contains SHIFT-JIS BIG_ENDIAN data.
 *
 *  There is only one text thread.
 *
 *  134e0553   cc               int3
 *  134e0554   77 0f            ja short 134e0565
 *  134e0556   c705 a8aa1001 34>mov dword ptr ds:[0x110aaa8],0x8853a34
 *  134e0560  -e9 9ffa03f0      jmp 03520004
 *  134e0565   8b35 74a71001    mov esi,dword ptr ds:[0x110a774]
 *  134e056b   d1e6             shl esi,1
 *  134e056d   c7c7 987db708    mov edi,0x8b77d98
 *  134e0573   03fe             add edi,esi
 *  134e0575   8b2d 78a71001    mov ebp,dword ptr ds:[0x110a778]
 *  134e057b   8bc7             mov eax,edi
 *  134e057d   81e0 ffffff3f    and eax,0x3fffffff
 *  134e0583   66:89a8 00004007 mov word ptr ds:[eax+0x7400000],bp ; jichi: hook here
 *  134e058a   8b2d 8c7df70f    mov ebp,dword ptr ds:[0xff77d8c]
 *  134e0590   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  134e0593   892d 8c7df70f    mov dword ptr ds:[0xff77d8c],ebp
 *  134e0599   8b05 e4a71001    mov eax,dword ptr ds:[0x110a7e4]
 *  134e059f   c705 74a71001 00>mov dword ptr ds:[0x110a774],0x8b70000
 *  134e05a9   892d 78a71001    mov dword ptr ds:[0x110a778],ebp
 *  134e05af   8935 7ca71001    mov dword ptr ds:[0x110a77c],esi
 *  134e05b5   8905 a8aa1001    mov dword ptr ds:[0x110aaa8],eax
 *  134e05bb   832d c4aa1001 0c sub dword ptr ds:[0x110aac4],0xc
 *  134e05c2  -e9 5cfa03f0      jmp 03520023
 */
// Read text from bp
// TODO: This should be expressed as general hook without extern fun
static void SpecialPSPHookNippon1(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  //LPCSTR text = LPCSTR(esp_base + pusha_ebp_off - 4); // ebp address
  LPCSTR text = LPCSTR(esp_base + hp->off); // dynamic offset, ebp or esi
  if (*text) {
    *data = (DWORD)text;
    *len = !text[0] ? 0 : !text[1] ? 1 : 2; // bp or si has at most two bytes
    //*len = ::LeadByteTable[*(BYTE *)text] // TODO: Test leadbytetable
    *split = regof(ecx, esp_base);
  }
}

bool InsertNippon1PSPHook()
{
  ConsoleOutput("vnreng: Nippon1 PSP: enter");

  const BYTE bytes[] =  {
    //0xcc,                         // 134e0553   cc               int3
    0x77, 0x0f,                     // 134e0554   77 0f            ja short 134e0565
    0xc7,0x05, XX8,                 // 134e0556   c705 a8aa1001 34>mov dword ptr ds:[0x110aaa8],0x8853a34
    0xe9, XX4,                      // 134e0560  -e9 9ffa03f0      jmp 03520004
    0x8b,0x35, XX4,                 // 134e0565   8b35 74a71001    mov esi,dword ptr ds:[0x110a774]
    0xd1,0xe6,                      // 134e056b   d1e6             shl esi,1
    0xc7,0xc7, XX4,                 // 134e056d   c7c7 987db708    mov edi,0x8b77d98
    0x03,0xfe,                      // 134e0573   03fe             add edi,esi
    0x8b,0x2d, XX4,                 // 134e0575   8b2d 78a71001    mov ebp,dword ptr ds:[0x110a778]
    0x8b,0xc7,                      // 134e057b   8bc7             mov eax,edi
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 134e057d   81e0 ffffff3f    and eax,0x3fffffff
    0x66,0x89,0xa8, XX4,            // 134e0583   66:89a8 00004007 mov word ptr ds:[eax+0x7400000],bp ; jichi: hook here
    0x8b,0x2d, XX4,                 // 134e058a   8b2d 8c7df70f    mov ebp,dword ptr ds:[0xff77d8c]
    0x8d,0x6d, 0x01                 // 134e0590   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
  };
  enum { memory_offset = 3 };
  enum { hook_offset = 0x134e0583 - 0x134e0554 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Nippon1 PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.off = pusha_ebp_off - 4; // ebp
    hp.type = USING_STRING|NO_CONTEXT;
    hp.text_fun = SpecialPSPHookNippon1;
    ConsoleOutput("vnreng: Nippon1 PSP: INSERT");
    NewHook(hp, L"Nippon1 PSP");
  }

  ConsoleOutput("vnreng: Nippon1 PSP: leave");
  return addr;
}

/** 7/26/2014 jichi: Alternative Nippon1 PSP engine, 0.9.8 only
 *  Sample game: 神々の悪戯 (0.9.8 only)
 *  Issue: character name cannot be extracted
 *
 *  Memory address is FIXED.
 *  Debug method: breakpoint the precomputed address
 *
 *  This function is the one that write the text into the memory.
 *
 *  13d13e8b   0f92c0           setb al
 *  13d13e8e   8bf8             mov edi,eax
 *  13d13e90   81ff 00000000    cmp edi,0x0
 *  13d13e96   893d 78a71001    mov dword ptr ds:[0x110a778],edi
 *  13d13e9c   8935 dca71001    mov dword ptr ds:[0x110a7dc],esi
 *  13d13ea2   0f85 16000000    jnz 13d13ebe
 *  13d13ea8   832d c4aa1001 0a sub dword ptr ds:[0x110aac4],0xa
 *  13d13eaf   c705 a8aa1001 cc>mov dword ptr ds:[0x110aaa8],0x887c2cc
 *  13d13eb9  -e9 65c1a3ef      jmp 03750023
 *  13d13ebe   832d c4aa1001 0a sub dword ptr ds:[0x110aac4],0xa
 *  13d13ec5   e9 0e000000      jmp 13d13ed8
 *  13d13eca   01a8 c28708e9    add dword ptr ds:[eax+0xe90887c2],ebp
 *  13d13ed0   4f               dec edi
 *  13d13ed1   c1a3 ef90cccc cc shl dword ptr ds:[ebx+0xcccc90ef],0xcc   ; shift constant out of range 1..31
 *  13d13ed8   77 0f            ja short 13d13ee9
 *  13d13eda   c705 a8aa1001 a8>mov dword ptr ds:[0x110aaa8],0x887c2a8
 *  13d13ee4  -e9 1bc1a3ef      jmp 03750004
 *  13d13ee9   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
 *  13d13eef   81e0 ffffff3f    and eax,0x3fffffff
 *  13d13ef5   0fb7b0 0000c007  movzx esi,word ptr ds:[eax+0x7c00000]
 *  13d13efc   8b3d fccd5a10    mov edi,dword ptr ds:[0x105acdfc]
 *  13d13f02   8bef             mov ebp,edi
 *  13d13f04   d1e5             shl ebp,1
 *  13d13f06   81c5 e8cd9a08    add ebp,0x89acde8
 *  13d13f0c   8bc5             mov eax,ebp
 *  13d13f0e   81e0 ffffff3f    and eax,0x3fffffff
 *  13d13f14   66:89b0 2000c007 mov word ptr ds:[eax+0x7c00020],si ; jichi: hook here
 *  13d13f1b   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
 *  13d13f1e   893d fccd5a10    mov dword ptr ds:[0x105acdfc],edi
 *  13d13f24   8b15 dca71001    mov edx,dword ptr ds:[0x110a7dc]
 *  13d13f2a   8d52 10          lea edx,dword ptr ds:[edx+0x10]
 *  13d13f2d   8b05 e4a71001    mov eax,dword ptr ds:[0x110a7e4]
 *  13d13f33   893d 78a71001    mov dword ptr ds:[0x110a778],edi
 *  13d13f39   c705 7ca71001 e8>mov dword ptr ds:[0x110a77c],0x89acde8
 *  13d13f43   8935 80a71001    mov dword ptr ds:[0x110a780],esi
 *  13d13f49   892d 84a71001    mov dword ptr ds:[0x110a784],ebp
 *  13d13f4f   8915 dca71001    mov dword ptr ds:[0x110a7dc],edx
 *  13d13f55   8905 a8aa1001    mov dword ptr ds:[0x110aaa8],eax
 *  13d13f5b   832d c4aa1001 0b sub dword ptr ds:[0x110aac4],0xb
 *  13d13f62  -e9 bcc0a3ef      jmp 03750023
 *  13d13f67   90               nop
 */
//static void SpecialPSPHookNippon2(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
//{
//  LPCSTR text = LPCSTR(esp_base + pusha_esi_off - 4); // esi address
//  if (*text) {
//    *data = (DWORD)text;
//    *len = !text[0] ? 0 : !text[1] ? 1 : 2; // bp has at most two bytes
//    //*len = ::LeadByteTable[*(BYTE *)text] // TODO: Test leadbytetable
//    *split = regof(ecx, esp_base);
//  }
//}

// 8/13/2014: 5pb might crash on 0.9.9.
bool InsertNippon2PSPHook()
{
  ConsoleOutput("vnreng: Nippon2 PSP: enter");

  const BYTE bytes[] =  {
    0xe9, XX4,                      // 13d13ee4  -e9 1bc1a3ef      jmp 03750004
    0x8b,0x05, XX4,                 // 13d13ee9   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13d13eef   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb7,0xb0, XX4,            // 13d13ef5   0fb7b0 0000c007  movzx esi,word ptr ds:[eax+0x7c00000]
    0x8b,0x3d, XX4,                 // 13d13efc   8b3d fccd5a10    mov edi,dword ptr ds:[0x105acdfc]
    0x8b,0xef,                      // 13d13f02   8bef             mov ebp,edi
    0xd1,0xe5,                      // 13d13f04   d1e5             shl ebp,1
    0x81,0xc5, XX4,                 // 13d13f06   81c5 e8cd9a08    add ebp,0x89acde8
    0x8b,0xc5,                      // 13d13f0c   8bc5             mov eax,ebp
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13d13f0e   81e0 ffffff3f    and eax,0x3fffffff
    0x66,0x89,0xb0 //, XX4          // 13d13f14   66:89b0 2000c007 mov word ptr ds:[eax+0x7c00020],si ; jichi: hook here
  };
  enum { memory_offset = 3 };
  enum { hook_offset = sizeof(bytes) - memory_offset };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Nippon2 PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.off = pusha_esi_off - 4; // esi
    hp.type = USING_STRING|NO_CONTEXT;
    hp.text_fun = SpecialPSPHookNippon1;
    ConsoleOutput("vnreng: Nippon2 PSP: INSERT");
    NewHook(hp, L"Nippon2 PSP");
  }

  ConsoleOutput("vnreng: Nippon2 PSP: leave");
  return addr;
}

/** 7/26/2014 jichi Broccoli PSP engine, 0.9.8, 0.9.9
 *  Sample game: 明治東亰恋伽 (works on both 0.9.8, 0.9.9)
 *
 *  Memory address is FIXED.
 *  Debug method: breakpoint the memory address
 *
 *  The data is in (WORD)dl in bytes.
 *
 *  There are two text threads.
 *  Only one is correct.
 *
 *  13d26cab   cc               int3
 *  13d26cac   77 0f            ja short 13d26cbd
 *  13d26cae   c705 a8aa1001 24>mov dword ptr ds:[0x110aaa8],0x886a724
 *  13d26cb8  -e9 4793ccef      jmp 039f0004
 *  13d26cbd   8b35 dca71001    mov esi,dword ptr ds:[0x110a7dc]
 *  13d26cc3   8db6 60feffff    lea esi,dword ptr ds:[esi-0x1a0]
 *  13d26cc9   8b3d e4a71001    mov edi,dword ptr ds:[0x110a7e4]
 *  13d26ccf   8bc6             mov eax,esi
 *  13d26cd1   81e0 ffffff3f    and eax,0x3fffffff
 *  13d26cd7   89b8 9001c007    mov dword ptr ds:[eax+0x7c00190],edi
 *  13d26cdd   8b2d 80a71001    mov ebp,dword ptr ds:[0x110a780]
 *  13d26ce3   0fbfed           movsx ebp,bp
 *  13d26ce6   8bd6             mov edx,esi
 *  13d26ce8   8bce             mov ecx,esi
 *  13d26cea   03cd             add ecx,ebp
 *  13d26cec   8935 dca71001    mov dword ptr ds:[0x110a7dc],esi
 *  13d26cf2   33c0             xor eax,eax
 *  13d26cf4   3bd1             cmp edx,ecx
 *  13d26cf6   0f92c0           setb al
 *  13d26cf9   8bf0             mov esi,eax
 *  13d26cfb   81fe 00000000    cmp esi,0x0
 *  13d26d01   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  13d26d07   890d 74a71001    mov dword ptr ds:[0x110a774],ecx
 *  13d26d0d   892d 80a71001    mov dword ptr ds:[0x110a780],ebp
 *  13d26d13   8915 8ca71001    mov dword ptr ds:[0x110a78c],edx
 *  13d26d19   0f85 16000000    jnz 13d26d35
 *  13d26d1f   832d c4aa1001 08 sub dword ptr ds:[0x110aac4],0x8
 *  13d26d26   e9 b9000000      jmp 13d26de4
 *  13d26d2b   0158 a7          add dword ptr ds:[eax-0x59],ebx
 *  13d26d2e   8608             xchg byte ptr ds:[eax],cl
 *  13d26d30  -e9 ee92ccef      jmp 039f0023
 *  13d26d35   832d c4aa1001 08 sub dword ptr ds:[0x110aac4],0x8
 *  13d26d3c   e9 0b000000      jmp 13d26d4c
 *  13d26d41   0144a7 86        add dword ptr ds:[edi-0x7a],eax
 *  13d26d45   08e9             or cl,ch
 *  13d26d47   d892 ccef9077    fcom dword ptr ds:[edx+0x7790efcc]
 *  13d26d4d   0fc7             ???                                      ; unknown command
 *  13d26d4f   05 a8aa1001      add eax,0x110aaa8
 *  13d26d54   44               inc esp
 *  13d26d55   a7               cmps dword ptr ds:[esi],dword ptr es:[ed>
 *  13d26d56   8608             xchg byte ptr ds:[eax],cl
 *  13d26d58  -e9 a792ccef      jmp 039f0004
 *  13d26d5d   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  13d26d63   81e0 ffffff3f    and eax,0x3fffffff
 *  13d26d69   0fb6b0 0000c007  movzx esi,byte ptr ds:[eax+0x7c00000]
 *  13d26d70   8b3d 7ca71001    mov edi,dword ptr ds:[0x110a77c]
 *  13d26d76   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
 *  13d26d79   8b05 8ca71001    mov eax,dword ptr ds:[0x110a78c]
 *  13d26d7f   81e0 ffffff3f    and eax,0x3fffffff
 *  13d26d85   8bd6             mov edx,esi
 *  13d26d87   8890 0000c007    mov byte ptr ds:[eax+0x7c00000],dl ; jichi: hook here, get byte from dl
 *  13d26d8d   8b2d 8ca71001    mov ebp,dword ptr ds:[0x110a78c]
 *  13d26d93   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  13d26d96   81fe 00000000    cmp esi,0x0
 *  13d26d9c   893d 7ca71001    mov dword ptr ds:[0x110a77c],edi
 *  13d26da2   8935 88a71001    mov dword ptr ds:[0x110a788],esi
 *  13d26da8   892d 8ca71001    mov dword ptr ds:[0x110a78c],ebp
 *  13d26dae   0f84 16000000    je 13d26dca
 *  13d26db4   832d c4aa1001 05 sub dword ptr ds:[0x110aac4],0x5
 *  13d26dbb   e9 f48b0100      jmp 13d3f9b4
 *  13d26dc0   0138             add dword ptr ds:[eax],edi
 *  13d26dc2   a7               cmps dword ptr ds:[esi],dword ptr es:[ed>
 *  13d26dc3   8608             xchg byte ptr ds:[eax],cl
 *  13d26dc5  -e9 5992ccef      jmp 039f0023
 *  13d26dca   832d c4aa1001 05 sub dword ptr ds:[0x110aac4],0x5
 *  13d26dd1   e9 0e000000      jmp 13d26de4
 *  13d26dd6   0158 a7          add dword ptr ds:[eax-0x59],ebx
 *  13d26dd9   8608             xchg byte ptr ds:[eax],cl
 *  13d26ddb  -e9 4392ccef      jmp 039f0023
 *  13d26de0   90               nop
 *  13d26de1   cc               int3
 */

// New line character for Broccoli games is '^'
static inline bool _broccoligarbage_ch(char c) { return c == '^'; }

// Read text from dl
static void SpecialPSPHookBroccoli(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD text = esp_base + pusha_edx_off - 4; // edx address
  char c = *(LPCSTR)text;
  if (c && !_broccoligarbage_ch(c)) {
    *data = text;
    *len = 1;
    *split = regof(ecx, esp_base);
  }
}

bool InsertBroccoliPSPHook()
{
  ConsoleOutput("vnreng: Broccoli PSP: enter");

  const BYTE bytes[] =  {
    0x0f,0xc7,                      // 13d26d4d   0fc7             ???                                      ; unknown command
    0x05, XX4,                      // 13d26d4f   05 a8aa1001      add eax,0x110aaa8
    0x44,                           // 13d26d54   44               inc esp
    0xa7,                           // 13d26d55   a7               cmps dword ptr ds:[esi],dword ptr es:[ed>
    0x86,0x08,                      // 13d26d56   8608             xchg byte ptr ds:[eax],cl
    0xe9, XX4,                      // 13d26d58  -e9 a792ccef      jmp 039f0004
    0x8b,0x05, XX4,                 // 13d26d5d   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
    // Following pattern is not sufficient
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13d26d63   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb0, XX4,            // 13d26d69   0fb6b0 0000c007  movzx esi,byte ptr ds:[eax+0x7c00000]
    0x8b,0x3d, XX4,                 // 13d26d70   8b3d 7ca71001    mov edi,dword ptr ds:[0x110a77c]
    0x8d,0x7f, 0x01,                // 13d26d76   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
    0x8b,0x05, XX4,                 // 13d26d79   8b05 8ca71001    mov eax,dword ptr ds:[0x110a78c]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13d26d7f   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xd6,                      // 13d26d85   8bd6             mov edx,esi
    0x88,0x90, XX4,                 // 13d26d87   8890 0000c007    mov byte ptr ds:[eax+0x7c00000],dl ; jichi: hook here, get byte from dl
    0x8b,0x2d, XX4,                 // 13d26d8d   8b2d 8ca71001    mov ebp,dword ptr ds:[0x110a78c]
    0x8d,0x6d, 0x01,                // 13d26d93   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
    0x81,0xfe, 0x00,0x00,0x00,0x00  // 13d26d96   81fe 00000000    cmp esi,0x0
  };
  enum { hook_offset = 0x13d26d87 - 0x13d26d4d };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Broccoli PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT;
    hp.text_fun = SpecialPSPHookBroccoli;
    //ITH_GROWL_DWORD(hp.addr);
    ConsoleOutput("vnreng: Broccoli PSP: INSERT");
    NewHook(hp, L"Broccoli PSP");
  }

  ConsoleOutput("vnreng: Broccoli PSP: leave");
  return addr;
}

/** 7/26/2014 jichi Otomate PSP engine, 0.9.8 only, 0.9.9 not work
 *  Replaced by Otomate PPSSPP on 0.9.9.
 *
 *  Sample game: クロノスタシア
 *  Sample game: フォトカノ (repetition)
 *
 *  Not work on 0.9.9: Amnesia Crowd
 *
 *  The instruction pattern also exist in 0.9.9. But the function is not called.
 *
 *  Memory address is FIXED.
 *  Debug method: breakpoint the memory address
 *
 *  The memory access of the function below is weird that the accessed value is 2 bytes after the real text.
 *
 *  PPSSPP 0.9.8, クロノスタシア
 *  13c00fe1   cc               int3
 *  13c00fe2   cc               int3
 *  13c00fe3   cc               int3
 *  13c00fe4   77 0f            ja short 13c00ff5
 *  13c00fe6   c705 a8aa1001 30>mov dword ptr ds:[0x110aaa8],0x884b330
 *  13c00ff0  -e9 0ff0edf2      jmp 06ae0004
 *  13c00ff5   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  13c00ffb   81e0 ffffff3f    and eax,0x3fffffff
 *  13c01001   0fbeb0 0000c007  movsx esi,byte ptr ds:[eax+0x7c00000] ; jichi: hook here
 *  13c01008   81fe 00000000    cmp esi,0x0 ; jichi: hook here, get the esi value
 *  13c0100e   8935 80a71001    mov dword ptr ds:[0x110a780],esi
 *  13c01014   0f84 25000000    je 13c0103f
 *  13c0101a   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
 *  13c01020   8d76 01          lea esi,dword ptr ds:[esi+0x1]
 *  13c01023   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  13c01029   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  13c01030  ^e9 afffffff      jmp 13c00fe4
 *  13c01035   0130             add dword ptr ds:[eax],esi
 *  13c01037   b3 84            mov bl,0x84
 *  13c01039   08e9             or cl,ch
 *  13c0103b   e4 ef            in al,0xef                               ; i/o command
 *  13c0103d   ed               in eax,dx                                ; i/o command
 *  13c0103e   f2:              prefix repne:                            ; superfluous prefix
 *  13c0103f   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  13c01046   e9 0d000000      jmp 13c01058
 *  13c0104b   013cb3           add dword ptr ds:[ebx+esi*4],edi
 *  13c0104e   8408             test byte ptr ds:[eax],cl
 *  13c01050  -e9 ceefedf2      jmp 06ae0023
 *  13c01055   90               nop
 *  13c01056   cc               int3
 *  13c01057   cc               int3
 */
// TODO: is reverse_strlen a better choice?
// Read text from esi
static void SpecialPSPHookOtomate(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  //static uniquemap uniq;
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value - 2); // -2 to read 1 word more from previous location
  if (*text) {
    *split = regof(ecx, esp_base); // this would cause lots of texts, but it works for all games
    //*split = regof(ecx, esp_base) & 0xff00; // only use higher bits
    *data = (DWORD)text;
    size_t sz = ::strlen(text);
    *len = sz == 3 ? 3 : 1; // handling the last two bytes
  }
}

bool InsertOtomatePSPHook()
{
  ConsoleOutput("vnreng: Otomate PSP: enter");
  const BYTE bytes[] =  {
    0x77, 0x0f,                     // 13c00fe4   77 0f            ja short 13c00ff5
    0xc7,0x05, XX8,                 // 13c00fe6   c705 a8aa1001 30>mov dword ptr ds:[0x110aaa8],0x884b330
    0xe9, XX4,                      // 13c00ff0  -e9 0ff0edf2      jmp 06ae0004
    0x8b,0x05, XX4,                 // 13c00ff5   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13c00ffb   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xbe,0xb0, XX4,            // 13c01001   0fbeb0 0000c007  movsx esi,byte ptr ds:[eax+0x7c00000] ; jichi: hook here
    0x81,0xfe, 0x00,0x00,0x00,0x00, // 13c01008   81fe 00000000    cmp esi,0x0
    0x89,0x35, XX4,                 // 13c0100e   8935 80a71001    mov dword ptr ds:[0x110a780],esi
    0x0f,0x84, 0x25,0x00,0x00,0x00, // 13c01014   0f84 25000000    je 13c0103f
    0x8b,0x35, XX4,                 // 13c0101a   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
    0x8d,0x76, 0x01,                // 13c01020   8d76 01          lea esi,dword ptr ds:[esi+0x1]
    0x89,0x35, XX4,                 // 13c01023   8935 78a71001    mov dword ptr ds:[0x110a778],esi
    0x83,0x2d, XX4, 0x03            // 13c01029   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
  };
  enum { memory_offset = 3 };
  //enum { hook_offset = 0x13c01008 - 0x13c00fe4 };
  enum { hook_offset = 0x13c01001- 0x13c00fe4 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  //ITH_GROWL_DWORD(addr);
  if (!addr)
    ConsoleOutput("vnreng: Otomate PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|NO_CONTEXT;
    hp.text_fun = SpecialPSPHookOtomate;
    ConsoleOutput("vnreng: Otomate PSP: INSERT");
    NewHook(hp, L"Otomate PSP");
  }

  ConsoleOutput("vnreng: Otomate PSP: leave");
  return addr;
}

/** 7/29/2014 jichi Otomate PPSSPP 0.9.9
 *  Sample game: Amnesia Crowd
 *  Sample game: Amnesia Later
 *
 *  006db4af   cc               int3
 *  006db4b0   8b15 b8ebaf00    mov edx,dword ptr ds:[0xafebb8]          ; ppssppwi.01134988
 *  006db4b6   56               push esi
 *  006db4b7   8b42 10          mov eax,dword ptr ds:[edx+0x10]
 *  006db4ba   25 ffffff3f      and eax,0x3fffffff
 *  006db4bf   0305 94411301    add eax,dword ptr ds:[0x1134194]
 *  006db4c5   8d70 01          lea esi,dword ptr ds:[eax+0x1]
 *  006db4c8   8a08             mov cl,byte ptr ds:[eax] ; jichi: hook here, get text in [eax]
 *  006db4ca   40               inc eax
 *  006db4cb   84c9             test cl,cl
 *  006db4cd  ^75 f9            jnz short ppssppwi.006db4c8
 *  006db4cf   2bc6             sub eax,esi
 *  006db4d1   8942 08          mov dword ptr ds:[edx+0x8],eax
 *  006db4d4   5e               pop esi
 *  006db4d5   8d0485 07000000  lea eax,dword ptr ds:[eax*4+0x7]
 *  006db4dc   c3               retn
 *  006db4dd   cc               int3
 */
static void SpecialPPSSPPHookOtomate(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  // 006db4b7   8b42 10          mov eax,dword ptr ds:[edx+0x10] ; jichi: hook here
  // 006db4ba   25 ffffff3f      and eax,0x3fffffff
  // 006db4bf   0305 94411301    add eax,dword ptr ds:[0x1134194]; jichi: ds offset
  // 006db4c5   8d70 01          lea esi,dword ptr ds:[eax+0x1]
  DWORD edx = regof(edx, esp_base);
  DWORD eax = *(DWORD *)(edx + 0x10);
  eax &= 0x3fffffff;
  eax += *(DWORD *)hp->user_value;

  //DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax);
  if (*text) {
    text = _bandailtrim(text); // the same as bandai PSP
    *data = (DWORD)text;
    *len = _bandaistrlen(text);

    *split = regof(ecx, esp_base); // the same as Otomate PSP hook
    //DWORD ecx = regof(ecx, esp_base); // the same as Otomate PSP hook
    //*split = ecx ? ecx : (FIXED_SPLIT_VALUE << 2);
    //*split = ecx & 0xffffff00; // skip cl which is used
  }
}
bool InsertOtomatePPSSPPHook()
{
  ULONG startAddress, stopAddress;
  if (!NtInspect::getCurrentMemoryRange(&startAddress, &stopAddress)) { // need accurate stopAddress
    ConsoleOutput("vnreng: Otomate PPSSPP: failed to get memory range");
    return false;
  }
  ConsoleOutput("vnreng: Otomate PPSSPP: enter");
  const BYTE bytes[] =  {
    0x8b,0x15, XX4,             // 006db4b0   8b15 b8ebaf00    mov edx,dword ptr ds:[0xafebb8]          ; ppssppwi.01134988
    0x56,                       // 006db4b6   56               push esi
    0x8b,0x42, 0x10,            // 006db4b7   8b42 10          mov eax,dword ptr ds:[edx+0x10] ; jichi: hook here
    0x25, 0xff,0xff,0xff,0x3f,  // 006db4ba   25 ffffff3f      and eax,0x3fffffff
    0x03,0x05, XX4,             // 006db4bf   0305 94411301    add eax,dword ptr ds:[0x1134194]; jichi: ds offset
    0x8d,0x70, 0x01,            // 006db4c5   8d70 01          lea esi,dword ptr ds:[eax+0x1]
    0x8a,0x08,                  // 006db4c8   8a08             mov cl,byte ptr ds:[eax] ; jichi: hook here
    0x40,                       // 006db4ca   40               inc eax
    0x84,0xc9,                  // 006db4cb   84c9             test cl,cl
    0x75, 0xf9,                 // 006db4cd  ^75 f9            jnz short ppssppwi.006db4c8
    0x2b,0xc6,                  // 006db4cf   2bc6             sub eax,esi
    0x89,0x42, 0x08,            // 006db4d1   8942 08          mov dword ptr ds:[edx+0x8],eax
    0x5e,                       // 006db4d4   5e               pop esi
    0x8d,0x04,0x85, 0x07,0x00,0x00,0x00  // 006db4d5   8d0485 07000000  lea eax,dword ptr ds:[eax*4+0x7]
  };
  //enum { hook_offset = 0x006db4c8 - 0x006db4b0 };
  enum { hook_offset = 0x006db4b7 - 0x006db4b0 };
  enum { ds_offset = 0x006db4bf - 0x006db4b0 + 2 };

  DWORD addr = SafeMatchBytes(bytes, sizeof(bytes), startAddress, stopAddress);
  //ITH_GROWL_DWORD(addr);
  if (!addr)
    ConsoleOutput("vnreng: Otomate PPSSPP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(addr + ds_offset); // this is the address after ds:[]
    hp.type = USING_STRING|NO_CONTEXT;
    hp.text_fun = SpecialPPSSPPHookOtomate;
    ConsoleOutput("vnreng: Otomate PPSSPP: INSERT");
    NewHook(hp, L"Otomate PPSSPP");
  }

  ConsoleOutput("vnreng: Otomate PPSSPP: leave");
  return addr;
}

#if 0 // FIXME: I am not able to find stable pattern in PSP 0.9.9.1

/** 9/21/2014 jichi Otomate PPSSPP 0.9.9.1
 *  Sample game: Amnesia Later
 *
 *  There are four fixed memory addresses.
 *  The two out of four can be used.
 *  (The other twos have loops or cannot be debugged).
 *
 *  This function is the same as PPSSPP 0.9.9.1 (?).
 *
 *  14039126   cc               int3
 *  14039127   cc               int3
 *  14039128   77 0f            ja short 14039139
 *  1403912a   c705 988e1301 3c>mov dword ptr ds:[0x1138e98],0x8922c3c
 *  14039134  -e9 cb6e83ef      jmp 03870004
 *  14039139   8b05 688b1301    mov eax,dword ptr ds:[0x1138b68]
 *  1403913f   81e0 ffffff3f    and eax,0x3fffffff
 *  14039145   0fbeb0 00000008  movsx esi,byte ptr ds:[eax+0x8000000]   ; jichi: text accessed, but looped
 *  1403914c   8b05 6c8b1301    mov eax,dword ptr ds:[0x1138b6c]
 *  14039152   81e0 ffffff3f    and eax,0x3fffffff
 *  14039158   0fbeb8 00000008  movsx edi,byte ptr ds:[eax+0x8000000]
 *  1403915f   3bf7             cmp esi,edi
 *  14039161   8935 748b1301    mov dword ptr ds:[0x1138b74],esi
 *  14039167   893d 7c8b1301    mov dword ptr ds:[0x1138b7c],edi
 *  1403916d   0f84 2f000000    je 140391a2
 *  14039173   8b05 688b1301    mov eax,dword ptr ds:[0x1138b68]
 *  14039179   81e0 ffffff3f    and eax,0x3fffffff
 *  1403917f   0fb6b0 00000008  movzx esi,byte ptr ds:[eax+0x8000000]   ; jichi: hook here
 *  14039186   8935 608b1301    mov dword ptr ds:[0x1138b60],esi
 *  1403918c   832d b48e1301 04 sub dword ptr ds:[0x1138eb4],0x4
 *  14039193   e9 24000000      jmp 140391bc
 *  14039198   0170 2c          add dword ptr ds:[eax+0x2c],esi
 *  1403919b   92               xchg eax,edx
 *  1403919c   08e9             or cl,ch
 *  1403919e   816e 83 ef832db4 sub dword ptr ds:[esi-0x7d],0xb42d83ef
 *  140391a5   8e13             mov ss,word ptr ds:[ebx]                 ; modification of segment register
 *  140391a7   0104e9           add dword ptr ds:[ecx+ebp*8],eax
 *  140391aa   b2 59            mov dl,0x59
 *  140391ac   0000             add byte ptr ds:[eax],al
 *  140391ae   014c2c 92        add dword ptr ss:[esp+ebp-0x6e],ecx
 *  140391b2   08e9             or cl,ch
 *  140391b4   6b6e 83 ef       imul ebp,dword ptr ds:[esi-0x7d],-0x11
 *  140391b8   90               nop
 *  140391b9   cc               int3
 *  140391ba   cc               int3
 */
// Get bytes in esi
static void SpecialPSPHookOtomate2(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  //static uniquemap uniq;
  DWORD text = esp_base + pusha_esi_off - 4;
  if (*(LPCSTR *)text) {
    *split = regof(ecx, esp_base); // this would cause lots of texts, but it works for all games
    *data = text;
    *len = 1;
  }
}

bool InsertOtomate2PSPHook()
{
  ConsoleOutput("vnreng: Otomate2 PSP: enter");
  const BYTE bytes[] =  {
    0x77, 0x0f,                     // 14039128   77 0f            ja short 14039139
    0xc7,0x05, XX8,                 // 1403912a   c705 988e1301 3c>mov dword ptr ds:[0x1138e98],0x8922c3c
    0xe9, XX4,                      // 14039134  -e9 cb6e83ef      jmp 03870004
    0x8b,0x05, XX4,                 // 14039139   8b05 688b1301    mov eax,dword ptr ds:[0x1138b68]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1403913f   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xbe,0xb0, XX4,            // 14039145   0fbeb0 00000008  movsx esi,byte ptr ds:[eax+0x8000000]   ; jichi: text accessed, but looped
    0x8b,0x05, XX4,                 // 1403914c   8b05 6c8b1301    mov eax,dword ptr ds:[0x1138b6c]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 14039152   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xbe,0xb8, XX4,            // 14039158   0fbeb8 00000008  movsx edi,byte ptr ds:[eax+0x8000000]
    0x3b,0xf7,                      // 1403915f   3bf7             cmp esi,edi
    0x89,0x35, XX4,                 // 14039161   8935 748b1301    mov dword ptr ds:[0x1138b74],esi
    0x89,0x3d, XX4,                 // 14039167   893d 7c8b1301    mov dword ptr ds:[0x1138b7c],edi
    0x0f,0x84, 0x2f,0x00,0x00,0x00, // 1403916d   0f84 2f000000    je 140391a2

    //0x8b,0x05, XX4,                 // 14039173   8b05 688b1301    mov eax,dword ptr ds:[0x1138b68]
    //0x81,0xe0, 0xff,0xff,0xff,0x3f, // 14039179   81e0 ffffff3f    and eax,0x3fffffff
    //0x0f,0xb6,0xb0, XX4,            // 1403917f   0fb6b0 00000008  movzx esi,byte ptr ds:[eax+0x8000000]   ; jichi: text accessed
    //0x89,0x35, XX4,                 // 14039186   8935 608b1301    mov dword ptr ds:[0x1138b60],esi   ; jichi: hook here, get lower bytes in esi
    //0x83,0x2d, XX4, 0x04            // 1403918c   832d b48e1301 04 sub dword ptr ds:[0x1138eb4],0x4
  };
  enum { hook_offset = 0x14039186 - 0x14039128 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr) {
    ConsoleOutput("vnreng: Otomate2 PSP: leave: first pattern not found");
    return false;
  }
  addr += hook_offset;

  //0x89,0x35, XX4,                 // 14039186   8935 608b1301    mov dword ptr ds:[0x1138b60],esi   ; jichi: hook here, get lower bytes in esi
  enum : WORD { mov_esi = 0x3589 };
  if (*(WORD *)addr != mov_esi) {
    ConsoleOutput("vnreng: Otomate2 PSP: leave: second pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = addr;
  hp.type = USING_STRING|NO_CONTEXT;
  hp.text_fun = SpecialPSPHookOtomate2;
  ConsoleOutput("vnreng: Otomate2 PSP: INSERT");
  NewHook(hp, L"Otomate PSP");

  ConsoleOutput("vnreng: Otomate2 PSP: leave");
  return addr;
}

#endif // 0

/** 7/27/2014 jichi Intense.jp PSP engine, 0.9.8, 0.9.9,
 *  Though Otomate can work, it cannot work line by line.
 *
 *  Sample game: 密室のサクリファイス work on 0.9.8 & 0.9.9
 *  This hook is only for intro graphic painting
 *
 *  Memory address is FIXED.
 *  Debug method: predict and breakpoint the memory address
 *
 *  There are two matches in the memory, and only one function accessing them.
 *  The memory is accessed by words.
 *
 *  The memory and hooked function is as follows.
 *
 *  09dfee77  88 c3 82 a2 95 a3 82 cc 89 9c 92 ea 82 c5 81 41  暗い淵の奥底で、
 *  09dfee87  92 e1 82 ad 81 41 8f ac 82 b3 82 ad 81 41 8b bf  低く、小さく、響
 *  09dfee97  82 ad 81 42 2a 70 0a 82 b1 82 ea 82 cd 81 41 8c  く。*p.これは、・
 *  09dfeea7  db 93 ae 81 63 81 48 2a 70 0a 82 c6 82 e0 82 b7  ﾛ動…？*p.ともす
 *  09dfeeb7  82 ea 82 ce 95 b7 82 ab 93 a6 82 b5 82 c4 82 b5  れば聞き逃してし
 *  09dfeec7  82 dc 82 a2 82 bb 82 a4 82 c8 81 41 2a 70 0a 8f  まいそうな、*p.・
 *  09dfeed7  ac 82 b3 82 ad 81 41 8e e3 81 58 82 b5 82 ad 81  ｬさく、弱々しく・
 *  09dfeee7  41 95 73 8a 6d 82 a9 82 c8 89 b9 81 42 00 00 00  a不確かな音。...
 *  09dfeef7  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *  09dfee07  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
 *
 *  13472227   90               nop
 *  13472228   77 0f            ja short 13472239
 *  1347222a   c705 a8aa1001 20>mov dword ptr ds:[0x110aaa8],0x884ce20
 *  13472234  -e9 cbdd16f0      jmp 035e0004
 *  13472239   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
 *  1347223f   81e0 ffffff3f    and eax,0x3fffffff
 *  13472245   8bb0 30004007    mov esi,dword ptr ds:[eax+0x7400030]
 *  1347224b   8b3d 84a71001    mov edi,dword ptr ds:[0x110a784]
 *  13472251   81c7 01000000    add edi,0x1
 *  13472257   8bee             mov ebp,esi
 *  13472259   032d 84a71001    add ebp,dword ptr ds:[0x110a784]
 *  1347225f   8bc5             mov eax,ebp
 *  13472261   81e0 ffffff3f    and eax,0x3fffffff
 *  13472267   0fbe90 00004007  movsx edx,byte ptr ds:[eax+0x7400000]   ; jichi: hook here
 *  1347226e   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
 *  13472274   81e0 ffffff3f    and eax,0x3fffffff
 *  1347227a   89b8 38004007    mov dword ptr ds:[eax+0x7400038],edi
 *  13472280   8bea             mov ebp,edx
 *  13472282   81e5 ff000000    and ebp,0xff
 *  13472288   81fa 0a000000    cmp edx,0xa
 *  1347228e   c705 70a71001 0a>mov dword ptr ds:[0x110a770],0xa
 *  13472298   8915 74a71001    mov dword ptr ds:[0x110a774],edx
 *  1347229e   893d 78a71001    mov dword ptr ds:[0x110a778],edi
 *  134722a4   892d 7ca71001    mov dword ptr ds:[0x110a77c],ebp
 *  134722aa   8935 80a71001    mov dword ptr ds:[0x110a780],esi
 *  134722b0   0f85 16000000    jnz 134722cc
 *  134722b6   832d c4aa1001 08 sub dword ptr ds:[0x110aac4],0x8
 *  134722bd   e9 02680000      jmp 13478ac4
 *  134722c2   01ec             add esp,ebp
 *  134722c4   ce               into
 *  134722c5   8408             test byte ptr ds:[eax],cl
 *  134722c7  -e9 57dd16f0      jmp 035e0023
 *  134722cc   832d c4aa1001 08 sub dword ptr ds:[0x110aac4],0x8
 *  134722d3   e9 0c000000      jmp 134722e4
 *  134722d8   0140 ce          add dword ptr ds:[eax-0x32],eax
 *  134722db   8408             test byte ptr ds:[eax],cl
 *  134722dd  -e9 41dd16f0      jmp 035e0023
 *  134722e2   90               nop
 *  134722e3   cc               int3
 */
// Read text from esi
static void SpecialPSPHookIntense(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  DWORD text = eax + hp->user_value;
  if (BYTE c = *(BYTE *)text) { // unsigned char
    *data = text;
    *len = ::LeadByteTable[c]; // 1 or 2
    //*split = regof(ecx, esp_base); // cause scenario text to split
    //*split = regof(edx, esp_base); // cause scenario text to split

    //*split = regof(ebx, esp_base); // works, but floating value
    *split = FIXED_SPLIT_VALUE * 3;
  }
}
bool InsertIntensePSPHook()
{
  ConsoleOutput("vnreng: Intense PSP: enter");
  const BYTE bytes[] =  {
    0x77, 0x0f,                     // 13472228   77 0f            ja short 13472239
    0xc7,0x05, XX8,                 // 1347222a   c705 a8aa1001 20>mov dword ptr ds:[0x110aaa8],0x884ce20
    0xe9, XX4,                      // 13472234  -e9 cbdd16f0      jmp 035e0004
    0x8b,0x05, XX4,                 // 13472239   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1347223f   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xb0, XX4,                 // 13472245   8bb0 30004007    mov esi,dword ptr ds:[eax+0x7400030]
    0x8b,0x3d, XX4,                 // 1347224b   8b3d 84a71001    mov edi,dword ptr ds:[0x110a784]
    0x81,0xc7, 0x01,0x00,0x00,0x00, // 13472251   81c7 01000000    add edi,0x1
    0x8b,0xee,                      // 13472257   8bee             mov ebp,esi
    0x03,0x2d, XX4,                 // 13472259   032d 84a71001    add ebp,dword ptr ds:[0x110a784]
    0x8b,0xc5,                      // 1347225f   8bc5             mov eax,ebp
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13472261   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xbe,0x90, XX4,            // 13472267   0fbe90 00004007  movsx edx,byte ptr ds:[eax+0x7400000]   ; jichi: hook here
    0x8b,0x05, XX4,                 // 1347226e   8b05 a8a71001    mov eax,dword ptr ds:[0x110a7a8]
    0x81,0xe0, 0xff,0xff,0xff,0x3f  // 13472274   81e0 ffffff3f    and eax,0x3fffffff
  };
  enum { memory_offset = 3 };
  enum { hook_offset = 0x13472267 - 0x13472228 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Intense PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|NO_CONTEXT;
    hp.text_fun = SpecialPSPHookIntense;
    ConsoleOutput("vnreng: Intense PSP: INSERT");
    NewHook(hp, L"Intense PSP");
  }

  ConsoleOutput("vnreng: Intense PSP: leave");
  return addr;
}

/** 8/12/2014 jichi Konami.jp PSP engine, 0.9.8, 0.9.9,
 *  Though Alchemist/Otomate can work, it has bad split that creates too many threads.
 *
 *  Sample game: 幻想水滸伝 紡がれし百年の時 on 0.9.8, 0.9.9
 *
 *  Memory address is FIXED.
 *  But hardware accesses are looped.
 *  Debug method: predict and breakpoint the memory address
 *
 *  There are two matches in the memory.
 *  Three looped functions are as follows.
 *  I randomply picked the first one.
 *
 *  It cannot extract character names.
 *
 *  14178f73   cc               int3
 *  14178f74   77 0f            ja short 14178f85
 *  14178f76   c705 c84c1301 a4>mov dword ptr ds:[0x1134cc8],0x88129a4
 *  14178f80  -e9 7f7071ef      jmp 03890004
 *  14178f85   8b05 c8491301    mov eax,dword ptr ds:[0x11349c8]
 *  14178f8b   81e0 ffffff3f    and eax,0x3fffffff
 *  14178f91   0fbeb0 00000008  movsx esi,byte ptr ds:[eax+0x8000000] ; jichi: hook here, loop
 *  14178f98   81fe 40000000    cmp esi,0x40
 *  14178f9e   8935 98491301    mov dword ptr ds:[0x1134998],esi
 *  14178fa4   c705 9c491301 40>mov dword ptr ds:[0x113499c],0x40
 *  14178fae   0f85 2f000000    jnz 14178fe3
 *  14178fb4   8b05 c8491301    mov eax,dword ptr ds:[0x11349c8]
 *  14178fba   81e0 ffffff3f    and eax,0x3fffffff
 *  14178fc0   0fbeb0 01000008  movsx esi,byte ptr ds:[eax+0x8000001]
 *  14178fc7   8935 98491301    mov dword ptr ds:[0x1134998],esi
 *  14178fcd   832d e44c1301 04 sub dword ptr ds:[0x1134ce4],0x4
 *  14178fd4   c705 c84c1301 d0>mov dword ptr ds:[0x1134cc8],0x88129d0
 *  14178fde  -e9 407071ef      jmp 03890023
 *  14178fe3   832d e44c1301 04 sub dword ptr ds:[0x1134ce4],0x4
 *  14178fea   e9 0d000000      jmp 14178ffc
 *  14178fef   01b429 8108e92a  add dword ptr ds:[ecx+ebp+0x2ae90881],es>
 *  14178ff6   70 71            jo short 14179069
 *  14178ff8   ef               out dx,eax                               ; i/o command
 *  14178ff9   90               nop
 *  14178ffa   cc               int3
 *
 *  1417a18c   77 0f            ja short 1417a19d
 *  1417a18e   c705 c84c1301 78>mov dword ptr ds:[0x1134cc8],0x8818378
 *  1417a198  -e9 675e71ef      jmp 03890004
 *  1417a19d   8b05 c8491301    mov eax,dword ptr ds:[0x11349c8]
 *  1417a1a3   81e0 ffffff3f    and eax,0x3fffffff
 *  1417a1a9   0fbeb0 00000008  movsx esi,byte ptr ds:[eax+0x8000000] ; jichi: hook here, loop
 *  1417a1b0   81fe 0a000000    cmp esi,0xa
 *  1417a1b6   8935 98491301    mov dword ptr ds:[0x1134998],esi
 *  1417a1bc   c705 9c491301 0a>mov dword ptr ds:[0x113499c],0xa
 *  1417a1c6   0f84 2e000000    je 1417a1fa
 *  1417a1cc   8b05 fc491301    mov eax,dword ptr ds:[0x11349fc]
 *  1417a1d2   81e0 ffffff3f    and eax,0x3fffffff
 *  1417a1d8   8bb0 18000008    mov esi,dword ptr ds:[eax+0x8000018]
 *  1417a1de   8935 98491301    mov dword ptr ds:[0x1134998],esi
 *  1417a1e4   832d e44c1301 04 sub dword ptr ds:[0x1134ce4],0x4
 *  1417a1eb   e9 24000000      jmp 1417a214
 *  1417a1f0   01b0 838108e9    add dword ptr ds:[eax+0xe9088183],esi
 *  1417a1f6   295e 71          sub dword ptr ds:[esi+0x71],ebx
 *  1417a1f9   ef               out dx,eax                               ; i/o command
 *  1417a1fa   832d e44c1301 04 sub dword ptr ds:[0x1134ce4],0x4
 *  1417a201   e9 1e660000      jmp 14180824
 *  1417a206   0188 838108e9    add dword ptr ds:[eax+0xe9088183],ecx
 *  1417a20c   135e 71          adc ebx,dword ptr ds:[esi+0x71]
 *  1417a20f   ef               out dx,eax                               ; i/o command
 *  1417a210   90               nop
 *  1417a211   cc               int3
 *  1417a212   cc               int3
 *
 *  1417a303   90               nop
 *  1417a304   77 0f            ja short 1417a315
 *  1417a306   c705 c84c1301 48>mov dword ptr ds:[0x1134cc8],0x8818448
 *  1417a310  -e9 ef5c71ef      jmp 03890004
 *  1417a315   8b35 dc491301    mov esi,dword ptr ds:[0x11349dc]
 *  1417a31b   8b3d 98491301    mov edi,dword ptr ds:[0x1134998]
 *  1417a321   33c0             xor eax,eax
 *  1417a323   3bf7             cmp esi,edi
 *  1417a325   0f9cc0           setl al
 *  1417a328   8bf8             mov edi,eax
 *  1417a32a   81ff 00000000    cmp edi,0x0
 *  1417a330   893d 98491301    mov dword ptr ds:[0x1134998],edi
 *  1417a336   0f84 2f000000    je 1417a36b
 *  1417a33c   8b05 c8491301    mov eax,dword ptr ds:[0x11349c8]
 *  1417a342   81e0 ffffff3f    and eax,0x3fffffff
 *  1417a348   0fbeb0 00000008  movsx esi,byte ptr ds:[eax+0x8000000] ; jichi: hook here, loop
 *  1417a34f   8935 98491301    mov dword ptr ds:[0x1134998],esi
 *  1417a355   832d e44c1301 03 sub dword ptr ds:[0x1134ce4],0x3
 *  1417a35c   e9 23000000      jmp 1417a384
 *  1417a361   018484 8108e9b8  add dword ptr ss:[esp+eax*4+0xb8e90881],>
 *  1417a368   5c               pop esp
 *  1417a369  ^71 ef            jno short 1417a35a
 *  1417a36b   832d e44c1301 03 sub dword ptr ds:[0x1134ce4],0x3
 *  1417a372   c705 c84c1301 54>mov dword ptr ds:[0x1134cc8],0x8818454
 *  1417a37c  -e9 a25c71ef      jmp 03890023
 *  1417a381   90               nop
 *  1417a382   cc               int3
 */
// Read text from looped address word by word
// Use reverse search to avoid looping issue assume the text is at fixed address.
static void SpecialPSPHookKonami(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  //static LPCSTR lasttext; // this value should be the same for the same game
  static size_t lastsize;

  DWORD eax = regof(eax, esp_base);
  LPCSTR cur = LPCSTR(eax + hp->user_value);
  if (!*cur)
    return;

  LPCSTR text = reverse_search_begin(cur);
  if (!text)
    return;
  //if (lasttext != text) {
  //  lasttext = text;
  //  lastsize = 0; // reset last size
  //}

  size_t size = ::strlen(text);
  if (size == lastsize)
    return;

  *len = lastsize = size;
  *data = (DWORD)text;

  *split = regof(ebx, esp_base); // ecx changes for each character, ebx is an address, edx is stable, but very large
}
bool InsertKonamiPSPHook()
{
  ConsoleOutput("vnreng: KONAMI PSP: enter");
  const BYTE bytes[] =  {
                                         // 14178f73   cc               int3
    0x77, 0x0f,                          // 14178f74   77 0f            ja short 14178f85
    0xc7,0x05, XX8,                      // 14178f76   c705 c84c1301 a4>mov dword ptr ds:[0x1134cc8],0x88129a4
    0xe9, XX4,                           // 14178f80  -e9 7f7071ef      jmp 03890004
    0x8b,0x05, XX4,                      // 14178f85   8b05 c8491301    mov eax,dword ptr ds:[0x11349c8]
    0x81,0xe0, 0xff,0xff,0xff,0x3f,      // 14178f8b   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xbe,0xb0, XX4,                 // 14178f91   0fbeb0 00000008  movsx esi,byte ptr ds:[eax+0x8000000] ; jichi: hook here, loop
    0x81,0xfe, 0x40,0x00,0x00,0x00,      // 14178f98   81fe 40000000    cmp esi,0x40
    0x89,0x35 //, XX4,                      // 14178f9e   8935 98491301    mov dword ptr ds:[0x1134998],esi
    //0xc7,0x05, XX4, 0x40,0x00,0x00,0x00,  // 14178fa4   c705 9c491301 40>mov dword ptr ds:[0x113499c],0x40
    //0x0f,0x85, 0x2f,0x00,0x00,0x00,0x00,  // 14178fae   0f85 2f000000    jnz 14178fe3
    //0x8b,0x05, XX4                        // 14178fb4   8b05 c8491301    mov eax,dword ptr ds:[0x11349c8]
  };
  enum { memory_offset = 3 };
  enum { hook_offset = 0x14178f91 - 0x14178f74 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: KONAMI PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|NO_CONTEXT;
    hp.text_fun = SpecialPSPHookKonami;
    ConsoleOutput("vnreng: KONAMI PSP: INSERT");
    NewHook(hp, L"KONAMI PSP");
  }

  ConsoleOutput("vnreng: KONAMI PSP: leave");
  return addr;
}

/** 8/9/2014 jichi Kadokawa.co.jp PSP engine, 0.9.8, ?,
 *
 *  Sample game: 未来日記 work on 0.9.8, not tested on 0.9.9
 *
 *  FIXME: Currently, only the character name works
 *
 *  Memory address is FIXED.
 *  Debug method: predict and breakpoint the memory address
 *
 *  There are two matches in the memory, and only one function accessing them.
 *
 *  Character name function is as follows.
 *  The scenario is the text after the name.
 *
 *  1348d79f   cc               int3
 *  1348d7a0   77 0f            ja short 1348d7b1
 *  1348d7a2   c705 a8aa1001 fc>mov dword ptr ds:[0x110aaa8],0x884c6fc
 *  1348d7ac  -e9 532844f0      jmp 038d0004
 *  1348d7b1   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  1348d7b7   81e0 ffffff3f    and eax,0x3fffffff
 *  1348d7bd   0fb6b0 00004007  movzx esi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
 *  1348d7c4   81fe 00000000    cmp esi,0x0
 *  1348d7ca   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  1348d7d0   0f85 2f000000    jnz 1348d805
 *  1348d7d6   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  1348d7dc   81e0 ffffff3f    and eax,0x3fffffff
 *  1348d7e2   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000]
 *  1348d7e9   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  1348d7ef   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  1348d7f6   c705 a8aa1001 5c>mov dword ptr ds:[0x110aaa8],0x884c75c
 *  1348d800  -e9 1e2844f0      jmp 038d0023
 *  1348d805   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  1348d80c   e9 0b000000      jmp 1348d81c
 *  1348d811   0108             add dword ptr ds:[eax],ecx
 *  1348d813   c78408 e9082844 >mov dword ptr ds:[eax+ecx+0x442808e9],0x>
 *  1348d81e   c705 a8aa1001 08>mov dword ptr ds:[0x110aaa8],0x884c708
 *  1348d828  -e9 d72744f0      jmp 038d0004
 *  1348d82d   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  1348d833   81e0 ffffff3f    and eax,0x3fffffff
 *  1348d839   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000]
 *  1348d840   81fe 00000000    cmp esi,0x0
 *  1348d846   8935 88a71001    mov dword ptr ds:[0x110a788],esi
 *  1348d84c   0f85 16000000    jnz 1348d868
 *  1348d852   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  1348d859   e9 aa030000      jmp 1348dc08
 *  1348d85e   0154c7 84        add dword ptr ds:[edi+eax*8-0x7c],edx
 *  1348d862   08e9             or cl,ch
 *  1348d864   bb 2744f083      mov ebx,0x83f04427
 *  1348d869   2d c4aa1001      sub eax,0x110aac4
 *  1348d86e   03e9             add ebp,ecx
 *  1348d870   0c 00            or al,0x0
 *  1348d872   0000             add byte ptr ds:[eax],al
 *  1348d874   0114c7           add dword ptr ds:[edi+eax*8],edx
 *  1348d877   8408             test byte ptr ds:[eax],cl
 *  1348d879  -e9 a52744f0      jmp 038d0023
 *  1348d87e   90               nop
 *  1348d87f   cc               int3
 *
 *  Scenario function is as follows.
 *  But I am not able to find it at runtime.
 *
 *  13484483   90               nop
 *  13484484   77 0f            ja short 13484495
 *  13484486   c705 a8aa1001 30>mov dword ptr ds:[0x110aaa8],0x884b030
 *  13484490  -e9 6fbb59f3      jmp 06a20004
 *  13484495   8b35 74a71001    mov esi,dword ptr ds:[0x110a774]
 *  1348449b   81fe 00000000    cmp esi,0x0
 *  134844a1   9c               pushfd
 *  134844a2   8bc6             mov eax,esi
 *  134844a4   8b35 84a71001    mov esi,dword ptr ds:[0x110a784]
 *  134844aa   03f0             add esi,eax
 *  134844ac   8935 74a71001    mov dword ptr ds:[0x110a774],esi
 *  134844b2   9d               popfd
 *  134844b3   0f8f 0c000000    jg 134844c5
 *  134844b9   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  134844c0  ^e9 23b0f9ff      jmp 1341f4e8
 *  134844c5   832d c4aa1001 02 sub dword ptr ds:[0x110aac4],0x2
 *  134844cc   e9 0b000000      jmp 134844dc
 *  134844d1   0138             add dword ptr ds:[eax],edi
 *  134844d3   b0 84            mov al,0x84
 *  134844d5   08e9             or cl,ch
 *  134844d7   48               dec eax
 *  134844d8   bb 59f39077      mov ebx,0x7790f359
 *  134844dd   0fc7             ???                                      ; unknown command
 *  134844df   05 a8aa1001      add eax,0x110aaa8
 *  134844e4   38b0 8408e917    cmp byte ptr ds:[eax+0x17e90884],dh
 *  134844ea   bb 59f38b05      mov ebx,0x58bf359
 *  134844ef  ^7c a7            jl short 13484498
 *  134844f1   1001             adc byte ptr ds:[ecx],al
 *  134844f3   81e0 ffffff3f    and eax,0x3fffffff
 *  134844f9   0fb6b0 00004007  movzx esi,byte ptr ds:[eax+0x7400000] ; jichi: hook here, byte by byte
 *  13484500   8b05 84a71001    mov eax,dword ptr ds:[0x110a784]
 *  13484506   81e0 ffffff3f    and eax,0x3fffffff
 *  1348450c   8bd6             mov edx,esi
 *  1348450e   8890 00004007    mov byte ptr ds:[eax+0x7400000],dl
 *  13484514   8b3d 84a71001    mov edi,dword ptr ds:[0x110a784]
 *  1348451a   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
 *  1348451d   8b2d 7ca71001    mov ebp,dword ptr ds:[0x110a77c]
 *  13484523   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  13484526   3b3d 74a71001    cmp edi,dword ptr ds:[0x110a774]
 *  1348452c   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  13484532   892d 7ca71001    mov dword ptr ds:[0x110a77c],ebp
 *  13484538   893d 84a71001    mov dword ptr ds:[0x110a784],edi
 *  1348453e   0f84 16000000    je 1348455a
 *  13484544   832d c4aa1001 05 sub dword ptr ds:[0x110aac4],0x5
 *  1348454b  ^e9 8cffffff      jmp 134844dc
 *  13484550   0138             add dword ptr ds:[eax],edi
 *  13484552   b0 84            mov al,0x84
 *  13484554   08e9             or cl,ch
 *  13484556   c9               leave
 *  13484557   ba 59f3832d      mov edx,0x2d83f359
 *  1348455c   c4aa 100105e9    les ebp,fword ptr ds:[edx+0xe9050110]    ; modification of segment register
 *  13484562   0e               push cs
 *  13484563   0000             add byte ptr ds:[eax],al
 *  13484565   0001             add byte ptr ds:[ecx],al
 *  13484567   4c               dec esp
 *  13484568   b0 84            mov al,0x84
 *  1348456a   08e9             or cl,ch
 *  1348456c   b3 ba            mov bl,0xba
 *  1348456e   59               pop ecx
 *  1348456f   f3:              prefix rep:                              ; superfluous prefix
 *  13484570   90               nop
 *  13484571   cc               int3
 *  13484572   cc               int3
 *  13484573   cc               int3
 */
bool InsertKadokawaNamePSPHook()
{
  ConsoleOutput("vnreng: Kadokawa Name PSP: enter");
  const BYTE bytes[] =  {
    0x77, 0x0f,                     // 1348d7a0   77 0f            ja short 1348d7b1
    0xc7,0x05, XX8,                 // 1348d7a2   c705 a8aa1001 fc>mov dword ptr ds:[0x110aaa8],0x884c6fc
    0xe9, XX4,                      // 1348d7ac  -e9 532844f0      jmp 038d0004
    0x8b,0x05, XX4,                 // 1348d7b1   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1348d7b7   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb0, XX4,            // 1348d7bd   0fb6b0 00004007  movzx esi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
    0x81,0xfe, 0x00,0x00,0x00,0x00, // 1348d7c4   81fe 00000000    cmp esi,0x0
    0x89,0x35, XX4,                 // 1348d7ca   8935 70a71001    mov dword ptr ds:[0x110a770],esi
    0x0f,0x85, 0x2f,0x00,0x00,0x00, // 1348d7d0   0f85 2f000000    jnz 1348d805
    0x8b,0x05, XX4,                 // 1348d7d6   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1348d7dc   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xbe,0xb0, XX4,            // 1348d7e2   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000]
    0x89,0x35 //, XX4,              // 1348d7e9   8935 70a71001    mov dword ptr ds:[0x110a770],esi
  };
  enum { memory_offset = 3 };
  enum { hook_offset = 0x1348d7bd - 0x1348d7a0 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Kadokawa Name PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT;
    hp.off = pusha_eax_off - 4;
    hp.split = pusha_edx_off - 4; // use edx to split repetition
    hp.text_fun = SpecialPSPHook;

    //ITH_GROWL_DWORD2(hp.addr, hp.user_value);
    ConsoleOutput("vnreng: Kadokawa Name PSP: INSERT");
    NewHook(hp, L"Kadokawa Name PSP");
  }

  ConsoleOutput("vnreng: Kadokawa Name PSP: leave");
  return addr;
}

/** 9/5/2014 jichi felistella.co.jp PSP engine, 0.9.8, 0.9.9
 *  Sample game: Summon Night 5 0.9.8/0.9.9
 *
 *  Encoding: utf8
 *  Fixed memory addresses: two matches
 *
 *  Debug method: predict the text and add break-points.
 *
 *  There are two good functions
 *  The second is used as it contains fewer garbage
 *
 *  // Not used
 *  14081173   cc               int3
 *  14081174   77 0f            ja short 14081185
 *  14081176   c705 c84c1301 40>mov dword ptr ds:[0x1134cc8],0x8989540
 *  14081180  -e9 7feef5f3      jmp 07fe0004
 *  14081185   8b35 9c491301    mov esi,dword ptr ds:[0x113499c]
 *  1408118b   8bc6             mov eax,esi
 *  1408118d   81e0 ffffff3f    and eax,0x3fffffff
 *  14081193   0fb6b8 00000008  movzx edi,byte ptr ds:[eax+0x8000000] ; jichi: hook here
 *  1408119a   8bef             mov ebp,edi
 *  1408119c   81e5 80000000    and ebp,0x80
 *  140811a2   8d76 01          lea esi,dword ptr ds:[esi+0x1]
 *  140811a5   81fd 00000000    cmp ebp,0x0
 *  140811ab   c705 90491301 00>mov dword ptr ds:[0x1134990],0x0
 *  140811b5   893d 9c491301    mov dword ptr ds:[0x113499c],edi
 *  140811bb   8935 a0491301    mov dword ptr ds:[0x11349a0],esi
 *  140811c1   892d a4491301    mov dword ptr ds:[0x11349a4],ebp
 *  140811c7   0f85 16000000    jnz 140811e3
 *  140811cd   832d e44c1301 06 sub dword ptr ds:[0x1134ce4],0x6
 *  140811d4   e9 fbf71200      jmp 141b09d4
 *  140811d9   01dc             add esp,ebx
 *  140811db   95               xchg eax,ebp
 *  140811dc   98               cwde
 *  140811dd   08e9             or cl,ch
 *  140811df   40               inc eax
 *
 *  // Used
 *  141be92f   cc               int3
 *  141be930   77 0f            ja short 141be941
 *  141be932   c705 c84c1301 0c>mov dword ptr ds:[0x1134cc8],0x8988f0c
 *  141be93c  -e9 c316e2f3      jmp 07fe0004
 *  141be941   8b35 98491301    mov esi,dword ptr ds:[0x1134998]
 *  141be947   8bc6             mov eax,esi
 *  141be949   81e0 ffffff3f    and eax,0x3fffffff
 *  141be94f   0fb6b8 00000008  movzx edi,byte ptr ds:[eax+0x8000000] ; jichi: hook here
 *  141be956   81ff 00000000    cmp edi,0x0
 *  141be95c   c705 90491301 00>mov dword ptr ds:[0x1134990],0x0
 *  141be966   893d 98491301    mov dword ptr ds:[0x1134998],edi
 *  141be96c   8935 9c491301    mov dword ptr ds:[0x113499c],esi
 *  141be972   0f85 16000000    jnz 141be98e
 *  141be978   832d e44c1301 04 sub dword ptr ds:[0x1134ce4],0x4
 *  141be97f   e9 e4020000      jmp 141bec68
 *  141be984   01748f 98        add dword ptr ds:[edi+ecx*4-0x68],esi
 *  141be988   08e9             or cl,ch
 *  141be98a   95               xchg eax,ebp
 *  141be98b   16               push ss
 *  141be98c  ^e2 f3            loopd short 141be981
 *  141be98e   832d e44c1301 04 sub dword ptr ds:[0x1134ce4],0x4
 *  141be995   e9 0e000000      jmp 141be9a8
 *  141be99a   011c8f           add dword ptr ds:[edi+ecx*4],ebx
 *  141be99d   98               cwde
 *  141be99e   08e9             or cl,ch
 *  141be9a0   7f 16            jg short 141be9b8
 *  141be9a2  ^e2 f3            loopd short 141be997
 *  141be9a4   90               nop
 *  141be9a5   cc               int3
 */
// Only split text when edi is eax
// The value of edi is either eax or 0
static void SpecialPSPHookFelistella(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value);
  if (text) {
    *len = ::strlen(text); // utf8
    *data = (DWORD)text;

    DWORD edi = regof(edi, esp_base);
    *split = FIXED_SPLIT_VALUE * (edi == eax ? 4 : 5);
  }
}
bool InsertFelistellaPSPHook()
{
  ConsoleOutput("vnreng: FELISTELLA PSP: enter");
  const BYTE bytes[] =  {
    //0xcc,                              // 141be92f   cc               int3
    0x77, 0x0f,                          // 141be930   77 0f            ja short 141be941
    0xc7,0x05, XX8,                      // 141be932   c705 c84c1301 0c>mov dword ptr ds:[0x1134cc8],0x8988f0c
    0xe9, XX4,                           // 141be93c  -e9 c316e2f3      jmp 07fe0004
    0x8b,0x35, XX4,                      // 141be941   8b35 98491301    mov esi,dword ptr ds:[0x1134998]
    0x8b,0xc6,                           // 141be947   8bc6             mov eax,esi
    0x81,0xe0, 0xff,0xff,0xff,0x3f,      // 141be949   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb8, XX4,                 // 141be94f   0fb6b8 00000008  movzx edi,byte ptr ds:[eax+0x8000000] ; jichi: hook here
    0x81,0xff, 0x00,0x00,0x00,0x00,      // 141be956   81ff 00000000    cmp edi,0x0
    0xc7,0x05, XX4, 0x00,0x00,0x00,0x00, // 141be95c   c705 90491301 00>mov dword ptr ds:[0x1134990],0x0
    0x89,0x3d, XX4,                      // 141be966   893d 98491301    mov dword ptr ds:[0x1134998],edi
    0x89,0x35, XX4,                      // 141be96c   8935 9c491301    mov dword ptr ds:[0x113499c],esi
    0x0f,0x85, XX4,                      // 141be972   0f85 16000000    jnz 141be98e
    0x83,0x2d, XX4, 0x04,                // 141be978   832d e44c1301 04 sub dword ptr ds:[0x1134ce4],0x4
    // Above is not sufficient
    0xe9, XX4,                           // 141be97f   e9 e4020000      jmp 141bec68
    0x01,0x74,0x8f, 0x98                 // 141be984   01748f 98        add dword ptr ds:[edi+ecx*4-0x68],esi
    //0x08,0xe9,                         // 141be988   08e9             or cl,ch
    // Below could be changed for different run
    //0x95,                              // 141be98a   95               xchg eax,ebp
    //0x16                               // 141be98b   16               push ss
  };
  enum { memory_offset = 3 };
  enum { hook_offset = 0x141be94f - 0x141be930 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  //ITH_GROWL_DWORD(addr);
  if (!addr)
    ConsoleOutput("vnreng: FELISTELLA PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|USING_UTF8|USING_SPLIT|NO_CONTEXT; // Fix the split value to merge all threads
    //hp.text_fun = SpecialPSPHook;
    hp.text_fun = SpecialPSPHookFelistella;
    hp.off = pusha_eax_off - 4;
    //hp.split = pusha_ecx_off - 4; // cause main thread to split
    //hp.split = pusha_edx_off - 4; // cause main thread to split for different lines
    ConsoleOutput("vnreng: FELISTELLA PSP: INSERT");
    NewHook(hp, L"FELISTELLA PSP");
  }

  ConsoleOutput("vnreng: FELISTELLA PSP: leave");
  return addr;
}


#if 0 // 8/9/2014 jichi: does not work

bool InsertKadokawaPSPHook()
{
  ConsoleOutput("vnreng: Kadokawa PSP: enter");
  const BYTE bytes[] =  {
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 134844f3   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb0, XX4,            // 134844f9   0fb6b0 00004007  movzx esi,byte ptr ds:[eax+0x7400000] ; jichi: hook here, byte by byte
    0x8b,0x05, XX4,                 // 13484500   8b05 84a71001    mov eax,dword ptr ds:[0x110a784]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13484506   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xd6,                      // 1348450c   8bd6             mov edx,esi
    0x88,0x90, XX4,                 // 1348450e   8890 00004007    mov byte ptr ds:[eax+0x7400000],dl
    0x8b,0x3d, XX4,                 // 13484514   8b3d 84a71001    mov edi,dword ptr ds:[0x110a784]
    0x8d,0x7f, 0x01,                // 1348451a   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
    0x8b,0x2d, XX4,                 // 1348451d   8b2d 7ca71001    mov ebp,dword ptr ds:[0x110a77c]
    0x8d,0x6d, 0x01,                // 13484523   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
    0x3b,0x3d, XX4,                 // 13484526   3b3d 74a71001    cmp edi,dword ptr ds:[0x110a774]
    0x89,0x35, XX4,                 // 1348452c   8935 70a71001    mov dword ptr ds:[0x110a770],esi
    0x89,0x2d, XX4,                 // 13484532   892d 7ca71001    mov dword ptr ds:[0x110a77c],ebp
    0x89,0x3d, XX4,                 // 13484538   893d 84a71001    mov dword ptr ds:[0x110a784],edi
    // Above is not sufficient
    //0x0f,0x84, XX4,                 // 1348453e   0f84 16000000    je 1348455a
    //0x83,0x2d, XX4, 0x05,           // 13484544   832d c4aa1001 05 sub dword ptr ds:[0x110aac4],0x5
    //0xe9, XX4,                      // 1348454b  ^e9 8cffffff      jmp 134844dc
    //0x01,0x38,                      // 13484550   0138             add dword ptr ds:[eax],edi
    //0xb0, 0x84,                     // 13484552   b0 84            mov al,0x84
    //0x08,0xe9                       // 13484554   08e9             or cl,ch
    // Below will change at runtime
  };
  enum { memory_offset = 3 };
  enum { hook_offset = 0x134844f9 - 0x134844f3 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr) {
    ConsoleOutput("vnreng: Kadokawa PSP: pattern not found");
    return false;
  }
  addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes), addr);
  addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes), addr);

  if (!addr)
    ConsoleOutput("vnreng: Kadokawa PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT;
    hp.off = pusha_eax_off - 4;
    hp.split = pusha_ecx_off - 4; // use edx to split repetition
    hp.length_offset = 1; // byte by byte
    hp.text_fun = SpecialPSPHook;

    //ITH_GROWL_DWORD2(hp.addr, hp.user_value);
    ConsoleOutput("vnreng: Kadokawa PSP: INSERT");
    NewHook(hp, L"Kadokawa PSP");
  }

  ConsoleOutput("vnreng: Kadokawa PSP: leave");
  return addr;
}
#endif // 0

#if 0 // 8/9/2014 jichi: cannot find a good function

/** 8/9/2014 jichi Typemoon.com PSP engine, 0.9.8, 0.9.9,
 *
 *  Sample game: Fate CCC
 *  This game is made by both TYPE-MOON and Imageepoch
 *  But the encoding is SHIFT-JIS than UTF-8 like other Imageepoch games.
 *  Otomate hook will produce significant amount of garbage.
 *
 *  Memory address is FIXED.
 *  There are two matches in the memory.
 *
 *  Debug method: breakpoint the memory address
 *  The hooked functions were looping which made it difficult to debug.
 *
 *  Two looped functions are as follows. The first one is used
 *  The second function is tested as bad.
 *
 *  Registers: (all of them are fixed except eax)
 *  EAX 08C91373
 *  ECX 00000016
 *  EDX 00000012
 *  EBX 0027A580
 *  ESP 0353E6D0
 *  EBP 0000000B
 *  ESI 0000001E
 *  EDI 00000001
 *  EIP 1351E14D
 *
 *  1351e12d   f0:90            lock nop                                 ; lock prefix is not allowed
 *  1351e12f   cc               int3
 *  1351e130   77 0f            ja short 1351e141
 *  1351e132   c705 a8aa1001 b8>mov dword ptr ds:[0x110aaa8],0x88ed7b8
 *  1351e13c  -e9 c31e27f0      jmp 03790004
 *  1351e141   8b05 aca71001    mov eax,dword ptr ds:[0x110a7ac]
 *  1351e147   81e0 ffffff3f    and eax,0x3fffffff
 *  1351e14d   0fbeb0 01004007  movsx esi,byte ptr ds:[eax+0x7400001] ; or jichi: hook here
 *  1351e154   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
 *  1351e15a   81e0 ffffff3f    and eax,0x3fffffff
 *  1351e160   8bb8 50004007    mov edi,dword ptr ds:[eax+0x7400050]
 *  1351e166   81e6 ff000000    and esi,0xff
 *  1351e16c   8bc6             mov eax,esi
 *  1351e16e   8b35 a8a71001    mov esi,dword ptr ds:[0x110a7a8]
 *  1351e174   0bf0             or esi,eax
 *  1351e176   c1e6 10          shl esi,0x10
 *  1351e179   c1fe 10          sar esi,0x10
 *  1351e17c   893d 78a71001    mov dword ptr ds:[0x110a778],edi
 *  1351e182   8935 7ca71001    mov dword ptr ds:[0x110a77c],esi
 *  1351e188   c705 e4a71001 d4>mov dword ptr ds:[0x110a7e4],0x88ed7d4
 *  1351e192   832d c4aa1001 07 sub dword ptr ds:[0x110aac4],0x7
 *  1351e199   e9 0e000000      jmp 1351e1ac
 *  1351e19e   01ac3e 8e08e97b  add dword ptr ds:[esi+edi+0x7be9088e],eb>
 *  1351e1a5   1e               push ds
 *  1351e1a6   27               daa
 *  1351e1a7   f0:90            lock nop                                 ; lock prefix is not allowed
 *  1351e1a9   cc               int3
 *
 *  13513f23   cc               int3
 *  13513f24   77 0f            ja short 13513f35
 *  13513f26   c705 a8aa1001 d4>mov dword ptr ds:[0x110aaa8],0x88e7bd4
 *  13513f30  -e9 cfc027f0      jmp 03790004
 *  13513f35   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  13513f3b   81e0 ffffff3f    and eax,0x3fffffff
 *  13513f41   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000]
 *  13513f48   8b3d 84a71001    mov edi,dword ptr ds:[0x110a784]
 *  13513f4e   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
 *  13513f51   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  13513f57   81e0 ffffff3f    and eax,0x3fffffff
 *  13513f5d   8bd6             mov edx,esi
 *  13513f5f   8890 00004007    mov byte ptr ds:[eax+0x7400000],dl ; jichi: bad hook
 *  13513f65   8b2d 78a71001    mov ebp,dword ptr ds:[0x110a778]
 *  13513f6b   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  13513f6e   33c0             xor eax,eax
 *  13513f70   3b3d 80a71001    cmp edi,dword ptr ds:[0x110a780]
 *  13513f76   0f9cc0           setl al
 *  13513f79   8bf0             mov esi,eax
 *  13513f7b   8b15 7ca71001    mov edx,dword ptr ds:[0x110a77c]
 *  13513f81   8d52 01          lea edx,dword ptr ds:[edx+0x1]
 *  13513f84   81fe 00000000    cmp esi,0x0
 *  13513f8a   892d 78a71001    mov dword ptr ds:[0x110a778],ebp
 *  13513f90   8915 7ca71001    mov dword ptr ds:[0x110a77c],edx
 *  13513f96   893d 84a71001    mov dword ptr ds:[0x110a784],edi
 *  13513f9c   8935 88a71001    mov dword ptr ds:[0x110a788],esi
 *  13513fa2   0f84 16000000    je 13513fbe
 *  13513fa8   832d c4aa1001 07 sub dword ptr ds:[0x110aac4],0x7
 *  13513faf  ^e9 70ffffff      jmp 13513f24
 *  13513fb4   01d4             add esp,edx
 *  13513fb6   7b 8e            jpo short 13513f46
 *  13513fb8   08e9             or cl,ch
 *  13513fba   65:c027 f0       shl byte ptr gs:[edi],0xf0               ; shift constant out of range 1..31
 *  13513fbe   832d c4aa1001 07 sub dword ptr ds:[0x110aac4],0x7
 *  13513fc5   e9 0e000000      jmp 13513fd8
 *  13513fca   01f0             add eax,esi
 *  13513fcc   7b 8e            jpo short 13513f5c
 *  13513fce   08e9             or cl,ch
 *  13513fd0   4f               dec edi
 *  13513fd1   c027 f0          shl byte ptr ds:[edi],0xf0               ; shift constant out of range 1..31
 *  13513fd4   90               nop
 *  13513fd5   cc               int3
 *  13513fd6   cc               int3
 */
// Read text from dl
static void SpecialPSPHookTypeMoon(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  DWORD text = eax + hp->user_value - 1; // the text is in the previous byte
  if (BYTE c = *(BYTE *)text) { // unsigned char
    *data = text;
    *len = ::LeadByteTable[c]; // 1 or 2
    //*split = regof(ecx, esp_base);
    //*split = regof(edx, esp_base);
    *split = regof(ebx, esp_base);
  }
}
bool InsertTypeMoonPSPHook()
{
  ConsoleOutput("vnreng: TypeMoon PSP: enter");
  const BYTE bytes[] =  {
    0x77, 0x0f,                     // 1351e130   77 0f            ja short 1351e141
    0xc7,0x05, XX8,                 // 1351e132   c705 a8aa1001 b8>mov dword ptr ds:[0x110aaa8],0x88ed7b8
    0xe9, XX4,                      // 1351e13c  -e9 c31e27f0      jmp 03790004
    0x8b,0x05, XX4,                 // 1351e141   8b05 aca71001    mov eax,dword ptr ds:[0x110a7ac]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1351e147   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xbe,0xb0, XX4,            // 1351e14d   0fbeb0 01004007  movsx esi,byte ptr ds:[eax+0x7400001] ;  jichi: hook here
    0x8b,0x05, XX4,                 // 1351e154   8b05 dca71001    mov eax,dword ptr ds:[0x110a7dc]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1351e15a   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xb8, XX4,                 // 1351e160   8bb8 50004007    mov edi,dword ptr ds:[eax+0x7400050]
    0x81,0xe6, 0xff,0x00,0x00,0x00, // 1351e166   81e6 ff000000    and esi,0xff
    0x8b,0xc6,                      // 1351e16c   8bc6             mov eax,esi
    0x8b,0x35, XX4,                 // 1351e16e   8b35 a8a71001    mov esi,dword ptr ds:[0x110a7a8]
    0x0b,0xf0,                      // 1351e174   0bf0             or esi,eax
    0xc1,0xe6, 0x10,                // 1351e176   c1e6 10          shl esi,0x10
    0xc1,0xfe, 0x10                 // 1351e179   c1fe 10          sar esi,0x10
  };
  enum { memory_offset = 3 };
  enum { hook_offset = 0x1351e14d - 0x1351e130 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: TypeMoon PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|NO_CONTEXT;
    hp.text_fun = SpecialPSPHookTypeMoon;
    ConsoleOutput("vnreng: TypeMoon PSP: INSERT");
    NewHook(hp, L"TypeMoon PSP");
  }

  ConsoleOutput("vnreng: TypeMoon PSP: leave");
  return addr;
}

#endif // 0

#if 0 // 7/25/2014: This function is not invoked? Why?
/** 7/22/2014 jichi: KOEI TECMO PSP, 0.9.8
 *  Sample game: 金色のコルダ3
 *
 *  134598e2   cc               int3
 *  134598e3   cc               int3
 *  134598e4   77 0f            ja short 134598f5
 *  134598e6   c705 a8aa1001 8c>mov dword ptr ds:[0x110aaa8],0x880f08c
 *  134598f0  -e9 0f67fbef      jmp 03410004
 *  134598f5   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  134598fb   81e0 ffffff3f    and eax,0x3fffffff
 *  13459901   8bb0 00004007    mov esi,dword ptr ds:[eax+0x7400000] ; jichi: hook here
 *  13459907   8b3d 7ca71001    mov edi,dword ptr ds:[0x110a77c]
 *  1345990d   8d7f 04          lea edi,dword ptr ds:[edi+0x4]
 *  13459910   8b05 84a71001    mov eax,dword ptr ds:[0x110a784]
 *  13459916   81e0 ffffff3f    and eax,0x3fffffff
 *  1345991c   89b0 00004007    mov dword ptr ds:[eax+0x7400000],esi
 *  13459922   8b2d 84a71001    mov ebp,dword ptr ds:[0x110a784]
 *  13459928   8d6d 04          lea ebp,dword ptr ss:[ebp+0x4]
 *  1345992b   8b15 78a71001    mov edx,dword ptr ds:[0x110a778]
 *  13459931   81fa 01000000    cmp edx,0x1
 *  13459937   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  1345993d   893d 7ca71001    mov dword ptr ds:[0x110a77c],edi
 *  13459943   892d 84a71001    mov dword ptr ds:[0x110a784],ebp
 *  13459949   c705 88a71001 01>mov dword ptr ds:[0x110a788],0x1
 *  13459953   0f84 16000000    je 1345996f
 *  13459959   832d c4aa1001 09 sub dword ptr ds:[0x110aac4],0x9
 *  13459960   e9 17000000      jmp 1345997c
 *  13459965   0190 f08008e9    add dword ptr ds:[eax+0xe90880f0],edx
 *  1345996b   b4 66            mov ah,0x66
 *  1345996d   fb               sti
 *  1345996e   ef               out dx,eax                               ; i/o command
 *  1345996f   832d c4aa1001 09 sub dword ptr ds:[0x110aac4],0x9
 *  13459976  ^e9 ddc1ffff      jmp 13455b58
 *  1345997b   90               nop
 */
bool InsertTecmoPSPHook()
{
  ConsoleOutput("vnreng: Tecmo PSP: enter");

  const BYTE bytes[] =  {
    0x77, 0x0f,                     // 134598e4   77 0f            ja short 134598f5
    0xc7,0x05, XX8,                 // 134598e6   c705 a8aa1001 8c>mov dword ptr ds:[0x110aaa8],0x880f08c
    0xe9, XX4,                      // 134598f0  -e9 0f67fbef      jmp 03410004
    0x8b,0x05, XX4,                 // 134598f5   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 134598fb   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xb0, XX4,                 // 13459901   8bb0 00004007    mov esi,dword ptr ds:[eax+0x7400000] ; jichi: hook here
    0x8b,0x3d, XX4,                 // 13459907   8b3d 7ca71001    mov edi,dword ptr ds:[0x110a77c]
    0x8d,0x7f, 0x04,                // 1345990d   8d7f 04          lea edi,dword ptr ds:[edi+0x4]
    0x8b,0x05, XX4,                 // 13459910   8b05 84a71001    mov eax,dword ptr ds:[0x110a784]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13459916   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0xb0 //, XX4,                 // 1345991c   89b0 00004007    mov dword ptr ds:[eax+0x7400000],esi
    //0x8b,0x2d, XX4,                 // 13459922   8b2d 84a71001    mov ebp,dword ptr ds:[0x110a784]
    //0x8d,0x6d, 0x04,                // 13459928   8d6d 04          lea ebp,dword ptr ss:[ebp+0x4]
    //0x8b,0x15, XX4,                 // 1345992b   8b15 78a71001    mov edx,dword ptr ds:[0x110a778]
    //0x81,0xfa, 0x01,0x00,0x00,0x00  // 13459931   81fa 01000000    cmp edx,0x1
  };
  enum { memory_offset = 2 };
  enum { hook_offset = 0x13459901 - 0x134598e4 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Tecmo PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.type = USING_STRING|USING_SPLIT|NO_CONTEXT;
    hp.off = pusha_eax_off - 4;
    hp.split = pusha_ecx_off - 4;
    hp.text_fun = SpecialPSPHook;
    ConsoleOutput("vnreng: Tecmo PSP: INSERT");
    NewHook(hp, L"Tecmo PSP");
  }

  ConsoleOutput("vnreng: Tecmo PSP: leave");
  return addr;
}
#endif // 0

/** jichi 7/19/2014 PCSX2
 *  Tested wit  pcsx2-v1.2.1-328-gef0e3fe-windows-x86, built at http://buildbot.orphis.net/pcsx2
 */
bool InsertPCSX2Hooks()
{
  // TODO: Add generic hooks
  return InsertTypeMoonPS2Hook()
      || InsertMarvelousPS2Hook()
      || InsertMarvelous2PS2Hook();
}

/** 7/19/2014 jichi
 *  Tested game: Fate/stay night [Realta Nua]
 *
 *  Fixed memory address.
 *  Text is incrementally increased.
 *
 *  Debug method: Debug next text location at \0.
 *  There are three locations that are OK to hook.
 *  The first one is used.
 *
 *  Runtime stack:
 *  0dc1f7e0   055be7c0
 *  0dc1f7e4   023105b0  pcsx2.023105b0
 *  0dc1f7e8   0dc1f804
 *  0dc1f7ec   023a406b  pcsx2.023a406b
 *  0dc1f7f0   00000000
 *  0dc1f7f4   000027e5
 *
 *  305a5424   2b05 809e9500    sub eax,dword ptr ds:[0x959e80]
 *  305a542a   0f88 05000000    js 305a5435
 *  305a5430  -e9 cbebdfd1      jmp pcsx2.023a4000
 *  305a5435   8b0d 20ac9600    mov ecx,dword ptr ds:[0x96ac20]
 *  305a543b   89c8             mov eax,ecx
 *  305a543d   c1e8 0c          shr eax,0xc
 *  305a5440   8b0485 30009e12  mov eax,dword ptr ds:[eax*4+0x129e0030]
 *  305a5447   bb 57545a30      mov ebx,0x305a5457
 *  305a544c   01c1             add ecx,eax
 *  305a544e  -0f88 ecbcd7d1    js pcsx2.02321140
 *  305a5454   0fbe01           movsx eax,byte ptr ds:[ecx] ; jichi: hook here
 *  305a5457   99               cdq
 *  305a5458   a3 f0ab9600      mov dword ptr ds:[0x96abf0],eax
 *  305a545d   8915 f4ab9600    mov dword ptr ds:[0x96abf4],edx
 *  305a5463   a1 40ac9600      mov eax,dword ptr ds:[0x96ac40]
 *  305a5468   3b05 f0ab9600    cmp eax,dword ptr ds:[0x96abf0]
 *  305a546e   75 11            jnz short 305a5481
 *  305a5470   a1 44ac9600      mov eax,dword ptr ds:[0x96ac44]
 *  305a5475   3b05 f4ab9600    cmp eax,dword ptr ds:[0x96abf4]
 *  305a547b   0f84 3a000000    je 305a54bb
 *  305a5481   8305 00ac9600 24 add dword ptr ds:[0x96ac00],0x24
 *  305a5488   9f               lahf
 *  305a5489   66:c1f8 0f       sar ax,0xf
 *  305a548d   98               cwde
 *  305a548e   a3 04ac9600      mov dword ptr ds:[0x96ac04],eax
 *  305a5493   c705 a8ad9600 6c>mov dword ptr ds:[0x96ada8],0x10e26c
 *  305a549d   a1 c0ae9600      mov eax,dword ptr ds:[0x96aec0]
 *  305a54a2   83c0 04          add eax,0x4
 *
 *  3038c78e  -0f88 ac4af9d1    js pcsx2.02321240
 *  3038c794   8911             mov dword ptr ds:[ecx],edx
 *  3038c796   8b0d 60ab9600    mov ecx,dword ptr ds:[0x96ab60]
 *  3038c79c   89c8             mov eax,ecx
 *  3038c79e   c1e8 0c          shr eax,0xc
 *  3038c7a1   8b0485 30009e12  mov eax,dword ptr ds:[eax*4+0x129e0030]
 *  3038c7a8   bb b8c73830      mov ebx,0x3038c7b8
 *  3038c7ad   01c1             add ecx,eax
 *  3038c7af  -0f88 8b49f9d1    js pcsx2.02321140
 *  3038c7b5   0fbe01           movsx eax,byte ptr ds:[ecx] ; jichi: or hook here
 *  3038c7b8   99               cdq
 *  3038c7b9   a3 e0ab9600      mov dword ptr ds:[0x96abe0],eax
 *  3038c7be   8915 e4ab9600    mov dword ptr ds:[0x96abe4],edx
 *  3038c7c4   c705 20ab9600 00>mov dword ptr ds:[0x96ab20],0x0
 *  3038c7ce   c705 24ab9600 00>mov dword ptr ds:[0x96ab24],0x0
 *  3038c7d8   c705 f0ab9600 25>mov dword ptr ds:[0x96abf0],0x25
 *  3038c7e2   c705 f4ab9600 00>mov dword ptr ds:[0x96abf4],0x0
 *  3038c7ec   833d e0ab9600 25 cmp dword ptr ds:[0x96abe0],0x25
 *  3038c7f3   75 0d            jnz short 3038c802
 *  3038c7f5   833d e4ab9600 00 cmp dword ptr ds:[0x96abe4],0x0
 *  3038c7fc   0f84 34000000    je 3038c836
 *  3038c802   31c0             xor eax,eax
 *
 *  304e1a0a   8b0d 40ab9600    mov ecx,dword ptr ds:[0x96ab40]
 *  304e1a10   89c8             mov eax,ecx
 *  304e1a12   c1e8 0c          shr eax,0xc
 *  304e1a15   8b0485 30009e12  mov eax,dword ptr ds:[eax*4+0x129e0030]
 *  304e1a1c   bb 2c1a4e30      mov ebx,0x304e1a2c
 *  304e1a21   01c1             add ecx,eax
 *  304e1a23  -0f88 17f7e3d1    js pcsx2.02321140
 *  304e1a29   0fbe01           movsx eax,byte ptr ds:[ecx] ; jichi: or hook here
 *  304e1a2c   99               cdq
 *  304e1a2d   a3 f0ab9600      mov dword ptr ds:[0x96abf0],eax
 *  304e1a32   8915 f4ab9600    mov dword ptr ds:[0x96abf4],edx
 *  304e1a38   a1 f0ab9600      mov eax,dword ptr ds:[0x96abf0]
 *  304e1a3d   3b05 d0ab9600    cmp eax,dword ptr ds:[0x96abd0]
 *  304e1a43   75 11            jnz short 304e1a56
 *  304e1a45   a1 f4ab9600      mov eax,dword ptr ds:[0x96abf4]
 *  304e1a4a   3b05 d4ab9600    cmp eax,dword ptr ds:[0x96abd4]
 *  304e1a50   0f84 3c000000    je 304e1a92
 *  304e1a56   a1 f0ab9600      mov eax,dword ptr ds:[0x96abf0]
 *  304e1a5b   83c0 d0          add eax,-0x30
 *  304e1a5e   99               cdq
 */
namespace { // unnamed
bool _typemoongarbage_ch(char c)
{
  return c == '%' || c == '.' || c == ' ' || c == ','
      || c >= '0' && c <= '9'
      || c >= 'A' && c <= 'z'; // also ignore ASCII 91-96: [ \ ] ^ _ `
}

// Trim leading garbage
LPCSTR _typemoonltrim(LPCSTR p)
{
  enum { MAX_LENGTH = VNR_TEXT_CAPACITY };
  if (p && p[0] == '%')
    for (int count = 0; (*p) && count < MAX_LENGTH; count++, p++)
      if (!_typemoongarbage_ch(*p))
        return p;
  return nullptr;
}

// Remove trailing garbage such as %n
size_t _typemoonstrlen(LPCSTR text)
{
  size_t len = ::strlen(text);
  size_t ret = len;
  while (len && _typemoongarbage_ch(text[len - 1])) {
    len--;
    if (text[len] == '%')
      ret = len;
  }
  return ret;
}

} // unnamed namespace

// Use last text size to determine
static void SpecialPS2HookTypeMoon(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  static LPCSTR lasttext; // this value should be the same for the same game
  static size_t lastsize;

  LPCSTR cur = LPCSTR(regof(ecx, esp_base));
  if (!*cur)
    return;

  LPCSTR text = reverse_search_begin(cur);
  if (!text)
    return;
  //text = _typemoonltrim(text);
  if (lasttext != text) {
    lasttext = text;
    lastsize = 0; // reset last size
  }

  size_t size = ::strlen(text);
  if (size == lastsize)
    return;
  if (size > lastsize) // incremental
    text += lastsize;
  lastsize = size;

  text = _typemoonltrim(text);
  size = _typemoonstrlen(text);
  //size = ::strlen(text);

  *data = (DWORD)text;
  *len = size;

  *split = FIXED_SPLIT_VALUE << 2; // merge all threads
  //*split = *(DWORD *)(esp_base + 4); // use [esp+4] as split
  //*split = regof(eax, esp_base);
  //*split = regof(esi, esp_base);
}

bool InsertTypeMoonPS2Hook()
{
  ConsoleOutput("vnreng: TypeMoon PS2: enter");
  const BYTE bytes[] =  {
    0x2b,0x05, XX4,       // 305a5424   2b05 809e9500    sub eax,dword ptr ds:[0x959e80]
    0x0f,0x88, 0x05,0x00,0x00,0x00, // 305a542a   0f88 05000000    js 305a5435
    0xe9, XX4,            // 305a5430  -e9 cbebdfd1      jmp pcsx2.023a4000
    0x8b,0x0d, XX4,       // 305a5435   8b0d 20ac9600    mov ecx,dword ptr ds:[0x96ac20]
    0x89,0xc8,            // 305a543b   89c8             mov eax,ecx
    0xc1,0xe8, 0x0c,      // 305a543d   c1e8 0c          shr eax,0xc
    0x8b,0x04,0x85, XX4,  // 305a5440   8b0485 30009e12  mov eax,dword ptr ds:[eax*4+0x129e0030]
    0xbb, XX4,            // 305a5447   bb 57545a30      mov ebx,0x305a5457
    0x01,0xc1,            // 305a544c   01c1             add ecx,eax
    // Following pattern is not sufficient
    0x0f,0x88, XX4,       // 305a544e  -0f88 ecbcd7d1    js pcsx2.02321140
    0x0f,0xbe,0x01,       // 305a5454   0fbe01           movsx eax,byte ptr ds:[ecx] ; jichi: hook here
    0x99,                 // 305a5457   99               cdq
    0xa3, XX4,            // 305a5458   a3 f0ab9600      mov dword ptr ds:[0x96abf0],eax
    0x89,0x15, XX4,       // 305a545d   8915 f4ab9600    mov dword ptr ds:[0x96abf4],edx
    0xa1, XX4,            // 305a5463   a1 40ac9600      mov eax,dword ptr ds:[0x96ac40]
    0x3b,0x05, XX4,       // 305a5468   3b05 f0ab9600    cmp eax,dword ptr ds:[0x96abf0]
    0x75, 0x11,           // 305a546e   75 11            jnz short 305a5481
    0xa1, XX4,            // 305a5470   a1 44ac9600      mov eax,dword ptr ds:[0x96ac44]
    0x3b,0x05, XX4,       // 305a5475   3b05 f4ab9600    cmp eax,dword ptr ds:[0x96abf4]
    0x0f,0x84, XX4,       // 305a547b   0f84 3a000000    je 305a54bb
    0x83,0x05, XX4, 0x24, // 305a5481   8305 00ac9600 24 add dword ptr ds:[0x96ac00],0x24
    0x9f,                 // 305a5488   9f               lahf
    0x66,0xc1,0xf8, 0x0f, // 305a5489   66:c1f8 0f       sar ax,0xf
    0x98                  // 305a548d   98               cwde
  };
  enum { hook_offset = 0x305a5454 - 0x305a5424 };

  DWORD addr = SafeMatchBytesInPS2Memory(bytes, sizeof(bytes));
  //addr = 0x30403967;
  if (!addr)
    ConsoleOutput("vnreng: TypeMoon PS2: pattern not found");
  else {
    //ITH_GROWL_DWORD(addr + hook_offset);
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.type = USING_STRING|NO_CONTEXT; // no context to get rid of return address
    hp.text_fun = SpecialPS2HookTypeMoon;
    //hp.off = pusha_ecx_off - 4; // ecx, get text in ds:[ecx]
    //hp.length_offset = 1;
    ConsoleOutput("vnreng: TypeMoon PS2: INSERT");
    //ITH_GROWL_DWORD(hp.addr);
    NewHook(hp, L"TypeMoon PS2");
  }

  ConsoleOutput("vnreng: TypeMoon PS2: leave");
  return addr;
}

/** 8/3/2014 jichi
 *  Tested game: School Rumble ねる娘は育つ
 *
 *  Fixed memory address.
 *  There is only one matched address.
 *
 *  Debug method: Predict text location.
 *  There are a couple of locations that are OK to hook.
 *  The last one is used.
 *
 *  Issue: the order of chara and scenario is reversed: 「scenario」chara
 *
 *  eax 20000000
 *  ecx 202d5ab3
 *  edx 00000000
 *  ebx 3026e299
 *  esp 0c14f910
 *  ebp 0c14f918
 *  esi 0014f470
 *  edi 00000000
 *  eip 3026e296
 *
 *  3026e1d5  -0f88 a530d7d2    js pcsx2.02fe1280
 *  3026e1db   0f1202           movlps xmm0,qword ptr ds:[edx]
 *  3026e1de   0f1301           movlps qword ptr ds:[ecx],xmm0
 *  3026e1e1   ba 10ac6201      mov edx,0x162ac10
 *  3026e1e6   8b0d d0ac6201    mov ecx,dword ptr ds:[0x162acd0]         ; pcsx2.01ffed00
 *  3026e1ec   83c1 10          add ecx,0x10
 *  3026e1ef   83e1 f0          and ecx,0xfffffff0
 *  3026e1f2   89c8             mov eax,ecx
 *  3026e1f4   c1e8 0c          shr eax,0xc
 *  3026e1f7   8b0485 30006d0d  mov eax,dword ptr ds:[eax*4+0xd6d0030]
 *  3026e1fe   bb 11e22630      mov ebx,0x3026e211
 *  3026e203   01c1             add ecx,eax
 *  3026e205  -0f88 b530d7d2    js pcsx2.02fe12c0
 *  3026e20b   0f280a           movaps xmm1,dqword ptr ds:[edx]
 *  3026e20e   0f2909           movaps dqword ptr ds:[ecx],xmm1
 *  3026e211   ba 00ac6201      mov edx,0x162ac00
 *  3026e216   8b0d d0ac6201    mov ecx,dword ptr ds:[0x162acd0]         ; pcsx2.01ffed00
 *  3026e21c   83e1 f0          and ecx,0xfffffff0
 *  3026e21f   89c8             mov eax,ecx
 *  3026e221   c1e8 0c          shr eax,0xc
 *  3026e224   8b0485 30006d0d  mov eax,dword ptr ds:[eax*4+0xd6d0030]
 *  3026e22b   bb 3ee22630      mov ebx,0x3026e23e
 *  3026e230   01c1             add ecx,eax
 *  3026e232  -0f88 8830d7d2    js pcsx2.02fe12c0
 *  3026e238   0f2812           movaps xmm2,dqword ptr ds:[edx]
 *  3026e23b   0f2911           movaps dqword ptr ds:[ecx],xmm2
 *  3026e23e   31c0             xor eax,eax
 *  3026e240   a3 f4ac6201      mov dword ptr ds:[0x162acf4],eax
 *  3026e245   c705 f0ac6201 d4>mov dword ptr ds:[0x162acf0],0x1498d4
 *  3026e24f   c705 a8ad6201 c0>mov dword ptr ds:[0x162ada8],0x1281c0
 *  3026e259   a1 c0ae6201      mov eax,dword ptr ds:[0x162aec0]
 *  3026e25e   83c0 07          add eax,0x7
 *  3026e261   a3 c0ae6201      mov dword ptr ds:[0x162aec0],eax
 *  3026e266   2b05 809e6101    sub eax,dword ptr ds:[0x1619e80]
 *  3026e26c   0f88 05000000    js 3026e277
 *  3026e272  -e9 895ddfd2      jmp pcsx2.03064000
 *  3026e277   8b0d 40ab6201    mov ecx,dword ptr ds:[0x162ab40]
 *  3026e27d   89c8             mov eax,ecx
 *  3026e27f   c1e8 0c          shr eax,0xc
 *  3026e282   8b0485 30006d0d  mov eax,dword ptr ds:[eax*4+0xd6d0030]
 *  3026e289   bb 99e22630      mov ebx,0x3026e299
 *  3026e28e   01c1             add ecx,eax
 *  3026e290  -0f88 6a2dd7d2    js pcsx2.02fe1000
 *  3026e296   0fb601           movzx eax,byte ptr ds:[ecx] ; jichi: hook here
 *  3026e299   a3 60ab6201      mov dword ptr ds:[0x162ab60],eax
 *  3026e29e   c705 64ab6201 00>mov dword ptr ds:[0x162ab64],0x0
 *  3026e2a8   a1 60ab6201      mov eax,dword ptr ds:[0x162ab60]
 *  3026e2ad   05 7fffffff      add eax,-0x81
 *  3026e2b2   99               cdq
 *  3026e2b3   a3 70ab6201      mov dword ptr ds:[0x162ab70],eax
 *  3026e2b8   8915 74ab6201    mov dword ptr ds:[0x162ab74],edx
 *  3026e2be   b8 01000000      mov eax,0x1
 *  3026e2c3   833d 74ab6201 00 cmp dword ptr ds:[0x162ab74],0x0
 *  3026e2ca   72 0d            jb short 3026e2d9
 *  3026e2cc   77 09            ja short 3026e2d7
 *  3026e2ce   833d 70ab6201 18 cmp dword ptr ds:[0x162ab70],0x18
 *  3026e2d5   72 02            jb short 3026e2d9
 *  3026e2d7   31c0             xor eax,eax
 *  3026e2d9   a3 10ab6201      mov dword ptr ds:[0x162ab10],eax
 *  3026e2de   c705 14ab6201 00>mov dword ptr ds:[0x162ab14],0x0
 *  3026e2e8   c705 20ab6201 00>mov dword ptr ds:[0x162ab20],0x0
 *  3026e2f2   c705 24ab6201 00>mov dword ptr ds:[0x162ab24],0x0
 *  3026e2fc   c705 30ab6201 00>mov dword ptr ds:[0x162ab30],0x0
 *  3026e306   c705 34ab6201 00>mov dword ptr ds:[0x162ab34],0x0
 *  3026e310   833d 10ab6201 00 cmp dword ptr ds:[0x162ab10],0x0
 *  3026e317   0f85 41000000    jnz 3026e35e
 *  3026e31d   833d 14ab6201 00 cmp dword ptr ds:[0x162ab14],0x0
 *  3026e324   0f85 34000000    jnz 3026e35e
 *  3026e32a   31c0             xor eax,eax
 *  3026e32c   a3 50ab6201      mov dword ptr ds:[0x162ab50],eax
 *  3026e331   a3 54ab6201      mov dword ptr ds:[0x162ab54],eax
 *  3026e336   c705 a8ad6201 c0>mov dword ptr ds:[0x162ada8],0x1285c0
 *  3026e340   a1 c0ae6201      mov eax,dword ptr ds:[0x162aec0]
 *  3026e345   83c0 08          add eax,0x8
 *  3026e348   a3 c0ae6201      mov dword ptr ds:[0x162aec0],eax
 *  3026e34d   2b05 809e6101    sub eax,dword ptr ds:[0x1619e80]
 *  3026e353   0f88 96280000    js 30270bef
 *  3026e359  -e9 a25cdfd2      jmp pcsx2.03064000
 *  3026e35e   31c0             xor eax,eax
 *  3026e360   a3 50ab6201      mov dword ptr ds:[0x162ab50],eax
 *  3026e365   a3 54ab6201      mov dword ptr ds:[0x162ab54],eax
 *  3026e36a   c705 a8ad6201 dc>mov dword ptr ds:[0x162ada8],0x1281dc
 *  3026e374   a1 c0ae6201      mov eax,dword ptr ds:[0x162aec0]
 *  3026e379   83c0 08          add eax,0x8
 *  3026e37c   a3 c0ae6201      mov dword ptr ds:[0x162aec0],eax
 *  3026e381   2b05 809e6101    sub eax,dword ptr ds:[0x1619e80]
 *  3026e387   0f88 a61f0000    js 30270333
 *  3026e38d  -e9 6e5cdfd2      jmp pcsx2.03064000
 *  3026e392   b8 01000000      mov eax,0x1
 *  3026e397   833d 64ab6201 00 cmp dword ptr ds:[0x162ab64],0x0
 *  3026e39e   7c 10            jl short 3026e3b0
 *  3026e3a0   7f 0c            jg short 3026e3ae
 *  3026e3a2   813d 60ab6201 80>cmp dword ptr ds:[0x162ab60],0x80
 *  3026e3ac   72 02            jb short 3026e3b0
 *  3026e3ae   31c0             xor eax,eax
 *  3026e3b0   a3 10ab6201      mov dword ptr ds:[0x162ab10],eax
 *  3026e3b5   c705 14ab6201 00>mov dword ptr ds:[0x162ab14],0x0
 *  3026e3bf   31c0             xor eax,eax
 *  3026e3c1   a3 54ab6201      mov dword ptr ds:[0x162ab54],eax
 *  3026e3c6   c705 50ab6201 01>mov dword ptr ds:[0x162ab50],0x1
 *  3026e3d0   c705 a8ad6201 e8>mov dword ptr ds:[0x162ada8],0x1285e8
 *  3026e3da   a1 c0ae6201      mov eax,dword ptr ds:[0x162aec0]
 *  3026e3df   83c0 03          add eax,0x3
 *  3026e3e2   a3 c0ae6201      mov dword ptr ds:[0x162aec0],eax
 *  3026e3e7   2b05 809e6101    sub eax,dword ptr ds:[0x1619e80]
 *  3026e3ed   0f88 05000000    js 3026e3f8
 *  3026e3f3  -e9 085cdfd2      jmp pcsx2.03064000
 *  3026e3f8   833d 10ab6201 00 cmp dword ptr ds:[0x162ab10],0x0
 *  3026e3ff   0f85 49000000    jnz 3026e44e
 *  3026e405   833d 14ab6201 00 cmp dword ptr ds:[0x162ab14],0x0
 *  3026e40c   0f85 3c000000    jnz 3026e44e
 *  3026e412   a1 60ab6201      mov eax,dword ptr ds:[0x162ab60]
 *  3026e417   c1e0 03          shl eax,0x3
 *  3026e41a   99               cdq
 *  3026e41b   a3 30ab6201      mov dword ptr ds:[0x162ab30],eax
 *  3026e420   8915 34ab6201    mov dword ptr ds:[0x162ab34],edx
 *  3026e426   c705 a8ad6201 04>mov dword ptr ds:[0x162ada8],0x128604
 *  3026e430   a1 c0ae6201      mov eax,dword ptr ds:[0x162aec0]
 *  3026e435   83c0 02          add eax,0x2
 *  3026e438   a3 c0ae6201      mov dword ptr ds:[0x162aec0],eax
 *  3026e43d   2b05 809e6101    sub eax,dword ptr ds:[0x1619e80]
 *  3026e443   0f88 93220000    js 302706dc
 *  3026e449  -e9 b25bdfd2      jmp pcsx2.03064000
 *  3026e44e   a1 60ab6201      mov eax,dword ptr ds:[0x162ab60]
 *  3026e453   c1e0 03          shl eax,0x3
 *  3026e456   99               cdq
 *  3026e457   a3 30ab6201      mov dword ptr ds:[0x162ab30],eax
 *  3026e45c   8915 34ab6201    mov dword ptr ds:[0x162ab34],edx
 *  3026e462   c705 a8ad6201 f0>mov dword ptr ds:[0x162ada8],0x1285f0
 *  3026e46c   a1 c0ae6201      mov eax,dword ptr ds:[0x162aec0]
 *  3026e471   83c0 02          add eax,0x2
 *  3026e474   a3 c0ae6201      mov dword ptr ds:[0x162aec0],eax
 *  3026e479   2b05 809e6101    sub eax,dword ptr ds:[0x1619e80]
 *  3026e47f   0f88 91270000    js 30270c16
 *  3026e485  -e9 765bdfd2      jmp pcsx2.03064000
 *  3026e48a   a1 30ab6201      mov eax,dword ptr ds:[0x162ab30]
 *  3026e48f   0305 60ab6201    add eax,dword ptr ds:[0x162ab60]
 *  3026e495   99               cdq
 *  3026e496   a3 30ab6201      mov dword ptr ds:[0x162ab30],eax
 *  3026e49b   8915 34ab6201    mov dword ptr ds:[0x162ab34],edx
 *  3026e4a1   a1 30ab6201      mov eax,dword ptr ds:[0x162ab30]
 *  3026e4a6   c1e0 05          shl eax,0x5
 *  3026e4a9   99               cdq
 *  3026e4aa   a3 30ab6201      mov dword ptr ds:[0x162ab30],eax
 *  3026e4af   8915 34ab6201    mov dword ptr ds:[0x162ab34],edx
 *  3026e4b5   a1 30ab6201      mov eax,dword ptr ds:[0x162ab30]
 *  3026e4ba   05 e01f2b00      add eax,0x2b1fe0
 *  3026e4bf   99               cdq
 *  3026e4c0   a3 20ab6201      mov dword ptr ds:[0x162ab20],eax
 *  3026e4c5   8915 24ab6201    mov dword ptr ds:[0x162ab24],edx
 *  3026e4cb   8b35 f0ac6201    mov esi,dword ptr ds:[0x162acf0]
 *  3026e4d1   8935 a8ad6201    mov dword ptr ds:[0x162ada8],esi
 *  3026e4d7   a1 c0ae6201      mov eax,dword ptr ds:[0x162aec0]
 *  3026e4dc   83c0 07          add eax,0x7
 *  3026e4df   a3 c0ae6201      mov dword ptr ds:[0x162aec0],eax
 *  3026e4e4   2b05 809e6101    sub eax,dword ptr ds:[0x1619e80]
 *  3026e4ea  -0f88 155bdfd2    js pcsx2.03064005
 *  3026e4f0  -e9 0b5bdfd2      jmp pcsx2.03064000
 *  3026e4f5   a1 20ab6201      mov eax,dword ptr ds:[0x162ab20]
 *  3026e4fa   8b15 24ab6201    mov edx,dword ptr ds:[0x162ab24]
 *  3026e500   a3 00ac6201      mov dword ptr ds:[0x162ac00],eax
 *  3026e505   8915 04ac6201    mov dword ptr ds:[0x162ac04],edx
 *  3026e50b   833d 00ac6201 00 cmp dword ptr ds:[0x162ac00],0x0
 *  3026e512   75 0d            jnz short 3026e521
 *  3026e514   833d 04ac6201 00 cmp dword ptr ds:[0x162ac04],0x0
 *  3026e51b   0f84 39000000    je 3026e55a
 *  3026e521   31c0             xor eax,eax
 */
// Use fixed split for this hook
static void SpecialPS2HookMarvelous(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD text = regof(ecx, esp_base);
  if (BYTE c = *(BYTE *)text) { // BYTE is unsigned
    *data = text;
    *len = ::LeadByteTable[c];
    *split = FIXED_SPLIT_VALUE * 3; // merge all threads
    //*split = regof(esi, esp_base);
    //*split = *(DWORD *)(esp_base + 4*5); // esp[5]
  }
}

bool InsertMarvelousPS2Hook()
{
  ConsoleOutput("vnreng: Marvelous PS2: enter");
  const BYTE bytes[] =  {
    0x2b,0x05, XX4,                     // 3026e266   2b05 809e6101    sub eax,dword ptr ds:[0x1619e80]
    0x0f,0x88, 0x05,0x00,0x00,0x00,     // 3026e26c   0f88 05000000    js 3026e277
    0xe9, XX4,                          // 3026e272  -e9 895ddfd2      jmp pcsx2.03064000
    0x8b,0x0d, XX4,                     // 3026e277   8b0d 40ab6201    mov ecx,dword ptr ds:[0x162ab40]
    0x89,0xc8,                          // 3026e27d   89c8             mov eax,ecx
    0xc1,0xe8, 0x0c,                    // 3026e27f   c1e8 0c          shr eax,0xc
    0x8b,0x04,0x85, XX4,                // 3026e282   8b0485 30006d0d  mov eax,dword ptr ds:[eax*4+0xd6d0030]
    0xbb, XX4,                          // 3026e289   bb 99e22630      mov ebx,0x3026e299
    0x01,0xc1,                          // 3026e28e   01c1             add ecx,eax
    0x0f,0x88, XX4,                     // 3026e290  -0f88 6a2dd7d2    js pcsx2.02fe1000
    0x0f,0xb6,0x01,                     // 3026e296   0fb601           movzx eax,byte ptr ds:[ecx] ; jichi: hook here
    0xa3, XX4,                          // 3026e299   a3 60ab6201      mov dword ptr ds:[0x162ab60],eax
    0xc7,0x05, XX4, 0x00,0x00,0x00,0x00,// 3026e29e   c705 64ab6201 00>mov dword ptr ds:[0x162ab64],0x0
    0xa1, XX4,                          // 3026e2a8   a1 60ab6201      mov eax,dword ptr ds:[0x162ab60]
    0x05, 0x7f,0xff,0xff,0xff,          // 3026e2ad   05 7fffffff      add eax,-0x81
    0x99,                               // 3026e2b2   99               cdq
    0xa3 //70ab6201                     // 3026e2b3   a3 70ab6201      mov dword ptr ds:[0x162ab70],eax
  };
  enum { hook_offset = 0x3026e296 - 0x3026e266 };

  DWORD addr = SafeMatchBytesInPS2Memory(bytes, sizeof(bytes));
  //addr = 0x30403967;
  if (!addr)
    ConsoleOutput("vnreng: Marvelous PS2: pattern not found");
  else {
    //ITH_GROWL_DWORD(addr + hook_offset);
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.type = USING_STRING|NO_CONTEXT; // no context to get rid of return address
    hp.text_fun = SpecialPS2HookMarvelous;
    //hp.off = pusha_ecx_off - 4; // ecx, get text in ds:[ecx]
    //hp.length_offset = 1;
    ConsoleOutput("vnreng: Marvelous PS2: INSERT");
    //ITH_GROWL_DWORD(hp.addr);
    NewHook(hp, L"Marvelous PS2");
  }

  ConsoleOutput("vnreng: Marvelous PS2: leave");
  return addr;
}

/** 8/3/2014 jichi
 *  Tested game: School Rumble 二学期
 *
 *  Fixed memory address.
 *  There is only one matched address.
 *
 *  Debug method: Breakpoint the memory address.
 *
 *  Issue: It cannot extract character name.
 *
 *  302072bd   a3 c0ae9e01      mov dword ptr ds:[0x19eaec0],eax
 *  302072c2   2b05 809e9d01    sub eax,dword ptr ds:[0x19d9e80]         ; cdvdgiga.5976f736
 *  302072c8  ^0f88 f3cafcff    js 301d3dc1
 *  302072ce  -e9 2dcd21d3      jmp pcsx2.03424000
 *  302072d3   8b0d 50ab9e01    mov ecx,dword ptr ds:[0x19eab50]
 *  302072d9   89c8             mov eax,ecx
 *  302072db   c1e8 0c          shr eax,0xc
 *  302072de   8b0485 3000e511  mov eax,dword ptr ds:[eax*4+0x11e50030]
 *  302072e5   bb f5722030      mov ebx,0x302072f5
 *  302072ea   01c1             add ecx,eax
 *  302072ec  -0f88 0e9d19d3    js pcsx2.033a1000
 *  302072f2   0fb601           movzx eax,byte ptr ds:[ecx]
 *  302072f5   a3 20ab9e01      mov dword ptr ds:[0x19eab20],eax
 *  302072fa   c705 24ab9e01 00>mov dword ptr ds:[0x19eab24],0x0
 *  30207304   8305 60ab9e01 ff add dword ptr ds:[0x19eab60],-0x1
 *  3020730b   9f               lahf
 *  3020730c   66:c1f8 0f       sar ax,0xf
 *  30207310   98               cwde
 *  30207311   a3 64ab9e01      mov dword ptr ds:[0x19eab64],eax
 *  30207316   8305 50ab9e01 01 add dword ptr ds:[0x19eab50],0x1
 *  3020731d   9f               lahf
 *  3020731e   66:c1f8 0f       sar ax,0xf
 *  30207322   98               cwde
 *  30207323   a3 54ab9e01      mov dword ptr ds:[0x19eab54],eax
 *  30207328   8b15 20ab9e01    mov edx,dword ptr ds:[0x19eab20]
 *  3020732e   8b0d 30ab9e01    mov ecx,dword ptr ds:[0x19eab30]
 *  30207334   89c8             mov eax,ecx
 *  30207336   c1e8 0c          shr eax,0xc
 *  30207339   8b0485 3000e511  mov eax,dword ptr ds:[eax*4+0x11e50030]
 *  30207340   bb 4f732030      mov ebx,0x3020734f
 *  30207345   01c1             add ecx,eax
 *  30207347  -0f88 739e19d3    js pcsx2.033a11c0
 *  3020734d   8811             mov byte ptr ds:[ecx],dl    ; jichi: hook here, text in dl
 *  3020734f   8305 30ab9e01 01 add dword ptr ds:[0x19eab30],0x1
 *  30207356   9f               lahf
 *  30207357   66:c1f8 0f       sar ax,0xf
 *  3020735b   98               cwde
 *  3020735c   a3 34ab9e01      mov dword ptr ds:[0x19eab34],eax
 *  30207361   a1 60ab9e01      mov eax,dword ptr ds:[0x19eab60]
 *  30207366   3b05 40ab9e01    cmp eax,dword ptr ds:[0x19eab40]
 *  3020736c   75 11            jnz short 3020737f
 *  3020736e   a1 64ab9e01      mov eax,dword ptr ds:[0x19eab64]
 *  30207373   3b05 44ab9e01    cmp eax,dword ptr ds:[0x19eab44]
 *  30207379   0f84 28000000    je 302073a7
 *  3020737f   c705 a8ad9e01 34>mov dword ptr ds:[0x19eada8],0x17eb34
 *  30207389   a1 c0ae9e01      mov eax,dword ptr ds:[0x19eaec0]
 *  3020738e   83c0 09          add eax,0x9
 *  30207391   a3 c0ae9e01      mov dword ptr ds:[0x19eaec0],eax
 *  30207396   2b05 809e9d01    sub eax,dword ptr ds:[0x19d9e80]         ; cdvdgiga.5976f736
 *  3020739c  ^0f88 31ffffff    js 302072d3
 *  302073a2  -e9 59cc21d3      jmp pcsx2.03424000
 *  302073a7   c705 a8ad9e01 50>mov dword ptr ds:[0x19eada8],0x17eb50
 *  302073b1   a1 c0ae9e01      mov eax,dword ptr ds:[0x19eaec0]
 *  302073b6   83c0 09          add eax,0x9
 *  302073b9   a3 c0ae9e01      mov dword ptr ds:[0x19eaec0],eax
 *  302073be   2b05 809e9d01    sub eax,dword ptr ds:[0x19d9e80]         ; cdvdgiga.5976f736
 *  302073c4  ^0f88 75cbfcff    js 301d3f3f
 *  302073ca  -e9 31cc21d3      jmp pcsx2.03424000
 *  302073cf   8b15 10ac9e01    mov edx,dword ptr ds:[0x19eac10]
 *  302073d5   8b0d 20ac9e01    mov ecx,dword ptr ds:[0x19eac20]
 *  302073db   83c1 04          add ecx,0x4
 *  302073de   89c8             mov eax,ecx
 *  302073e0   c1e8 0c          shr eax,0xc
 *  302073e3   8b0485 3000e511  mov eax,dword ptr ds:[eax*4+0x11e50030]
 *  302073ea   bb f9732030      mov ebx,0x302073f9
 *  302073ef   01c1             add ecx,eax
 *  302073f1  -0f88 499e19d3    js pcsx2.033a1240
 *  302073f7   8911             mov dword ptr ds:[ecx],edx
 *  302073f9   c705 a8ad9e01 5c>mov dword ptr ds:[0x19eada8],0x18d25c
 *  30207403   a1 c0ae9e01      mov eax,dword ptr ds:[0x19eaec0]
 *  30207408   83c0 03          add eax,0x3
 *  3020740b   a3 c0ae9e01      mov dword ptr ds:[0x19eaec0],eax
 *  30207410   2b05 809e9d01    sub eax,dword ptr ds:[0x19d9e80]         ; cdvdgiga.5976f736
 *  30207416   0f88 05000000    js 30207421
 *  3020741c  -e9 dfcb21d3      jmp pcsx2.03424000
 *  30207421   a1 50ac9e01      mov eax,dword ptr ds:[0x19eac50]
 *  30207426   05 00a2ffff      add eax,0xffffa200
 *  3020742b   99               cdq
 *  3020742c   a3 00ac9e01      mov dword ptr ds:[0x19eac00],eax
 *  30207431   8915 04ac9e01    mov dword ptr ds:[0x19eac04],edx
 *  30207437   31d2             xor edx,edx
 *  30207439   8b0d d0ac9e01    mov ecx,dword ptr ds:[0x19eacd0]
 *  3020743f   89c8             mov eax,ecx
 *  30207441   c1e8 0c          shr eax,0xc
 *  30207444   8b0485 3000e511  mov eax,dword ptr ds:[eax*4+0x11e50030]
 *  3020744b   bb 5a742030      mov ebx,0x3020745a
 *  30207450   01c1             add ecx,eax
 *  30207452  -0f88 e89d19d3    js pcsx2.033a1240
 *  30207458   8911             mov dword ptr ds:[ecx],edx
 *  3020745a   a1 00ac9e01      mov eax,dword ptr ds:[0x19eac00]
 *  3020745f   8b15 04ac9e01    mov edx,dword ptr ds:[0x19eac04]
 */
// Use fixed split for this hook
static void SpecialPS2HookMarvelous2(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD text = esp_base + pusha_edx_off - 4; // get text in dl: 3020734d   8811  mov byte ptr ds:[ecx],dl
  if (BYTE c = *(BYTE *)text) { // BYTE is unsigned
    *data = text;
    *len = 1;
    //*split = FIXED_SPLIT_VALUE * 4; // merge all threads
    *split = regof(esi, esp_base);
    //*split = *(DWORD *)(esp_base + 4*5); // esp[5]
  }
}

bool InsertMarvelous2PS2Hook()
{
  ConsoleOutput("vnreng: Marvelous2 PS2: enter");
  const BYTE bytes[] =  {
    // The following pattern is not sufficient
    0x89,0xc8,            // 30207334   89c8             mov eax,ecx
    0xc1,0xe8, 0x0c,      // 30207336   c1e8 0c          shr eax,0xc
    0x8b,0x04,0x85, XX4,  // 30207339   8b0485 3000e511  mov eax,dword ptr ds:[eax*4+0x11e50030]
    0xbb, XX4,            // 30207340   bb 4f732030      mov ebx,0x3020734f
    0x01,0xc1,            // 30207345   01c1             add ecx,eax
    0x0f,0x88, XX4,       // 30207347  -0f88 739e19d3    js pcsx2.033a11c0
    0x88,0x11,            // 3020734d   8811             mov byte ptr ds:[ecx],dl    ; jichi: hook here, text in dl
    0x83,0x05, XX4, 0x01, // 3020734f   8305 30ab9e01 01 add dword ptr ds:[0x19eab30],0x1
    0x9f,                 // 30207356   9f               lahf
    0x66,0xc1,0xf8, 0x0f, // 30207357   66:c1f8 0f       sar ax,0xf
    0x98,                 // 3020735b   98               cwde
    // The above pattern is not sufficient
    0xa3, XX4,            // 3020735c   a3 34ab9e01      mov dword ptr ds:[0x19eab34],eax
    0xa1, XX4,            // 30207361   a1 60ab9e01      mov eax,dword ptr ds:[0x19eab60]
    0x3b,0x05, XX4,       // 30207366   3b05 40ab9e01    cmp eax,dword ptr ds:[0x19eab40]
    0x75, 0x11,           // 3020736c   75 11            jnz short 3020737f
    0xa1, XX4,            // 3020736e   a1 64ab9e01      mov eax,dword ptr ds:[0x19eab64]
    0x3b,0x05, XX4,       // 30207373   3b05 44ab9e01    cmp eax,dword ptr ds:[0x19eab44]
    0x0f,0x84, XX4,       // 30207379   0f84 28000000    je 302073a7
    0xc7,0x05, XX8,       // 3020737f   c705 a8ad9e01 34>mov dword ptr ds:[0x19eada8],0x17eb34
    // The above pattern is not sufficient
    0xa1, XX4,            // 30207389   a1 c0ae9e01      mov eax,dword ptr ds:[0x19eaec0]
    0x83,0xc0, 0x09,      // 3020738e   83c0 09          add eax,0x9
    0xa3, XX4,            // 30207391   a3 c0ae9e01      mov dword ptr ds:[0x19eaec0],eax
    0x2b,0x05, XX4,       // 30207396   2b05 809e9d01    sub eax,dword ptr ds:[0x19d9e80]         ; cdvdgiga.5976f736
    0x0f,0x88, XX4,       // 3020739c  ^0f88 31ffffff    js 302072d3
    0xe9, XX4,            // 302073a2  -e9 59cc21d3      jmp pcsx2.03424000
    0xc7,0x05, XX8,       // 302073a7   c705 a8ad9e01 50>mov dword ptr ds:[0x19eada8],0x17eb50
    0xa1, XX4,            // 302073b1   a1 c0ae9e01      mov eax,dword ptr ds:[0x19eaec0]
    0x83,0xc0, 0x09,      // 302073b6   83c0 09          add eax,0x9
    0xa3, XX4,            // 302073b9   a3 c0ae9e01      mov dword ptr ds:[0x19eaec0],eax
    0x2b,0x05, XX4,       // 302073be   2b05 809e9d01    sub eax,dword ptr ds:[0x19d9e80]         ; cdvdgiga.5976f736
    0x0f,0x88, XX4,       // 302073c4  ^0f88 75cbfcff    js 301d3f3f
    0xe9, XX4,            // 302073ca  -e9 31cc21d3      jmp pcsx2.03424000
    0x8b,0x15, XX4,       // 302073cf   8b15 10ac9e01    mov edx,dword ptr ds:[0x19eac10]
    0x8b,0x0d, XX4,       // 302073d5   8b0d 20ac9e01    mov ecx,dword ptr ds:[0x19eac20]
    0x83,0xc1, 0x04,      // 302073db   83c1 04          add ecx,0x4
    0x89,0xc8,            // 302073de   89c8             mov eax,ecx
    0xc1,0xe8, 0x0c,      // 302073e0   c1e8 0c          shr eax,0xc
    0x8b,0x04,0x85, XX4,  // 302073e3   8b0485 3000e511  mov eax,dword ptr ds:[eax*4+0x11e50030]
    0xbb, XX4,            // 302073ea   bb f9732030      mov ebx,0x302073f9
    0x01,0xc1             // 302073ef   01c1             add ecx,eax
  };
  enum { hook_offset = 0x3020734d - 0x30207334 };

  DWORD addr = SafeMatchBytesInPS2Memory(bytes, sizeof(bytes));
  //addr = 0x30403967;
  if (!addr)
    ConsoleOutput("vnreng: Marvelous2 PS2: pattern not found");
  else {
    //ITH_GROWL_DWORD(addr + hook_offset);
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.type = USING_STRING|NO_CONTEXT; // no context to get rid of return address
    hp.text_fun = SpecialPS2HookMarvelous2;
    //hp.off = pusha_ecx_off - 4; // ecx, get text in ds:[ecx]
    //hp.length_offset = 1;
    ConsoleOutput("vnreng: Marvelous2 PS2: INSERT");
    //ITH_GROWL_DWORD(hp.addr);
    NewHook(hp, L"Marvelous2 PS2");
  }

  ConsoleOutput("vnreng: Marvelous2 PS2: leave");
  return addr;
}

#if 0 // jichi 7/19/2014: duplication text

/** 7/19/2014 jichi
 *  Tested game: .hack//G.U. Vol.1
 */
bool InsertNamcoPS2Hook()
{
  ConsoleOutput("vnreng: Namco PS2: enter");
  const BYTE bytes[1] =  {
  };
  enum { hook_offset = 0 };

  //DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  //DWORD addr = 0x303baf26;
  DWORD addr = 0x303C4B72;
  if (!addr)
    ConsoleOutput("vnreng: Namco PS2: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.type = USING_STRING|USING_SPLIT; // no context to get rid of return address
    hp.off = pusha_ecx_off - 4; // ecx
    hp.split = hp.off; // use ecx address to split
    ConsoleOutput("vnreng: Namco PS2: INSERT");
    //ITH_GROWL_DWORD(hp.addr);
    NewHook(hp, L"Namco PS2");
  }

  ConsoleOutput("vnreng: Namco PS2: leave");
  return addr;
}
#endif // 0

} // namespace Engine

// EOF

#if 0 // SEGA: loop text. BANDAI and Imageepoch should be sufficient
/** 7/25/2014 jichi sega.jp PSP engine
 *  Sample game: Shining Hearts
 *  Encoding: UTF-8
 *
 *  Debug method: simply add hardware break points to the matched memory
 *  All texts are in the memory.
 *  There are two memory addresses, but only one function addresses them.
 *
 *  This function seems to be the same as Tecmo?
 *
 *  13513476   f0:90            lock nop                                 ; lock prefix is not allowed
 *  13513478   77 0f            ja short 13513489
 *  1351347a   c705 a8aa1001 38>mov dword ptr ds:[0x110aaa8],0x89cae38
 *  13513484  -e9 7bcb4ff0      jmp 03a10004
 *  13513489   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
 *  1351348f   81e0 ffffff3f    and eax,0x3fffffff
 *  13513495   8bb0 00004007    mov esi,dword ptr ds:[eax+0x7400000] ; jichi: there are too many garbage here
 *  1351349b   8b3d 7ca71001    mov edi,dword ptr ds:[0x110a77c]
 *  135134a1   8d7f 04          lea edi,dword ptr ds:[edi+0x4]
 *  135134a4   8b05 84a71001    mov eax,dword ptr ds:[0x110a784]
 *  135134aa   81e0 ffffff3f    and eax,0x3fffffff
 *  135134b0   89b0 00004007    mov dword ptr ds:[eax+0x7400000],esi ; extract from esi
 *  135134b6   8b2d 84a71001    mov ebp,dword ptr ds:[0x110a784]
 *  135134bc   8d6d 04          lea ebp,dword ptr ss:[ebp+0x4]
 *  135134bf   8b15 78a71001    mov edx,dword ptr ds:[0x110a778]
 *  135134c5   81fa 01000000    cmp edx,0x1
 *  135134cb   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  135134d1   893d 7ca71001    mov dword ptr ds:[0x110a77c],edi
 *  135134d7   892d 84a71001    mov dword ptr ds:[0x110a784],ebp
 *  135134dd   c705 88a71001 01>mov dword ptr ds:[0x110a788],0x1
 *  135134e7   0f84 16000000    je 13513503
 *  135134ed   832d c4aa1001 09 sub dword ptr ds:[0x110aac4],0x9
 *  135134f4   e9 23000000      jmp 1351351c
 *  135134f9   013cae           add dword ptr ds:[esi+ebp*4],edi
 *  135134fc   9c               pushfd
 *  135134fd   08e9             or cl,ch
 *  135134ff   20cb             and bl,cl
 *  13513501   4f               dec edi
 *  13513502   f0:832d c4aa1001>lock sub dword ptr ds:[0x110aac4],0x9    ; lock prefix
 *  1351350a   e9 b1000000      jmp 135135c0
 *  1351350f   015cae 9c        add dword ptr ds:[esi+ebp*4-0x64],ebx
 *  13513513   08e9             or cl,ch
 *  13513515   0acb             or cl,bl
 *  13513517   4f               dec edi
 *  13513518   f0:90            lock nop                                 ; lock prefix is not allowed
 *  1351351a   cc               int3
 *  1351351b   cc               int3
 */
// Read text from esi
static void SpecialPSPHookSega(DWORD esp_base, HookParam *, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  LPCSTR text = LPCSTR(esp_base + pusha_esi_off - 4); // esi address
  if (*text) {
    *data = (DWORD)text;
    *len = !text[0] ? 0 : !text[1] ? 1 : text[2] ? 2 : text[3] ? 3 : 4;
    *split = regof(ebx, esp_base);
  }
}

bool InsertSegaPSPHook()
{
  ConsoleOutput("vnreng: SEGA PSP: enter");
  const BYTE bytes[] =  {
    0x77, 0x0f,                     // 13513478   77 0f            ja short 13513489
    0xc7,0x05, XX8,                 // 1351347a   c705 a8aa1001 38>mov dword ptr ds:[0x110aaa8],0x89cae38
    0xe9, XX4,                      // 13513484  -e9 7bcb4ff0      jmp 03a10004
    0x8b,0x05, XX4,                 // 13513489   8b05 7ca71001    mov eax,dword ptr ds:[0x110a77c]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 1351348f   81e0 ffffff3f    and eax,0x3fffffff
    0x8b,0xb0, XX4,                 // 13513495   8bb0 00004007    mov esi,dword ptr ds:[eax+0x7400000] ; jichi: here are too many garbage
    0x8b,0x3d, XX4,                 // 1351349b   8b3d 7ca71001    mov edi,dword ptr ds:[0x110a77c]
    0x8d,0x7f, 0x04,                // 135134a1   8d7f 04          lea edi,dword ptr ds:[edi+0x4]
    0x8b,0x05, XX4,                 // 135134a4   8b05 84a71001    mov eax,dword ptr ds:[0x110a784]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 135134aa   81e0 ffffff3f    and eax,0x3fffffff
    0x89,0xb0   //, XX4,            // 135134b0   89b0 00004007    mov dword ptr ds:[eax+0x7400000],esi ; jichi: hook here, get text in esi
  };
  enum { memory_offset = 2 };
  enum { hook_offset = sizeof(bytes) - memory_offset };
  //enum { hook_offset = 0x13513495 - 0x13513478 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: SEGA PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.type = USING_STRING|NO_CONTEXT; // UTF-8
    hp.text_fun = SpecialPSPHookSega;
    ConsoleOutput("vnreng: SEGA PSP: INSERT");
    NewHook(hp, L"SEGA PSP");
  }

  ConsoleOutput("vnreng: SEGA PSP: leave");
  return addr;
}
#endif // 0


#if 0 // jichi 7/14/2014: TODO there is text duplication issue?

/** 7/13/2014 jichi SHADE.co.jp PSP engine
 *  Sample game: とある科学の超電磁砲 (b-railgun.iso)
 *
 *  CheatEngine/Ollydbg shew there are 4 memory hits to full text in SHIFT-JIS.
 *  CheatEngine is not able to trace JIT instructions.
 *  Ollydbg can track the latter two memory accesses > 0x1ffffffff
 *
 *  The third access is 12ab3d64. There is one write access and 3 read accesses.
 *  But all the accesses are in a loop.
 *  So, the extracted text would suffer from infinite loop problem.
 *
 *  Memory range: 0x0400000 - 139f000
 *
 *  13400e10   90               nop
 *  13400e11   cc               int3
 *  13400e12   cc               int3
 *  13400e13   cc               int3
 *  13400e14   77 0f            ja short 13400e25
 *  13400e16   c705 a8aa1001 08>mov dword ptr ds:[0x110aaa8],0x88c1308
 *  13400e20  -e9 dff161f3      jmp 06a20004
 *  13400e25   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
 *  13400e2b   81c6 01000000    add esi,0x1
 *  13400e31   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  13400e37   81e0 ffffff3f    and eax,0x3fffffff
 *  13400e3d   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000] ; jichi: the data is in [eax+0x7400000]
 *  13400e44   8b2d 78a71001    mov ebp,dword ptr ds:[0x110a778]
 *  13400e4a   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
 *  13400e4d   81ff 00000000    cmp edi,0x0
 *  13400e53   8935 70a71001    mov dword ptr ds:[0x110a770],esi
 *  13400e59   893d 74a71001    mov dword ptr ds:[0x110a774],edi
 *  13400e5f   892d 78a71001    mov dword ptr ds:[0x110a778],ebp
 *  13400e65   0f84 16000000    je 13400e81
 *  13400e6b   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  13400e72   e9 21000000      jmp 13400e98
 *  13400e77   010c13           add dword ptr ds:[ebx+edx],ecx
 *  13400e7a   8c08             mov word ptr ds:[eax],cs
 *  13400e7c  -e9 a2f161f3      jmp 06a20023
 *  13400e81   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  13400e88   e9 7f000000      jmp 13400f0c
 *  13400e8d   0118             add dword ptr ds:[eax],ebx
 *  13400e8f   138c08 e98cf161  adc ecx,dword ptr ds:[eax+ecx+0x61f18ce9>
 *  13400e96   f3:              prefix rep:                              ; superfluous prefix
 *  13400e97   90               nop
 *  13400e98   77 0f            ja short 13400ea9
 *  13400e9a   c705 a8aa1001 0c>mov dword ptr ds:[0x110aaa8],0x88c130c
 *  13400ea4  -e9 5bf161f3      jmp 06a20004
 *  13400ea9   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  13400eaf   81e0 ffffff3f    and eax,0x3fffffff
 *  13400eb5   0fb6b0 00004007  movzx esi,byte ptr ds:[eax+0x7400000]
 *  13400ebc   8b3d 78a71001    mov edi,dword ptr ds:[0x110a778]
 *  13400ec2   8d7f 01          lea edi,dword ptr ds:[edi+0x1]
 *  13400ec5   81fe 00000000    cmp esi,0x0
 *  13400ecb   8935 74a71001    mov dword ptr ds:[0x110a774],esi
 *  13400ed1   893d 78a71001    mov dword ptr ds:[0x110a778],edi
 *  13400ed7   0f84 16000000    je 13400ef3
 *  13400edd   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  13400ee4  ^e9 afffffff      jmp 13400e98
 *  13400ee9   010c13           add dword ptr ds:[ebx+edx],ecx
 *  13400eec   8c08             mov word ptr ds:[eax],cs
 *  13400eee  -e9 30f161f3      jmp 06a20023
 *  13400ef3   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  13400efa   e9 0d000000      jmp 13400f0c
 *  13400eff   0118             add dword ptr ds:[eax],ebx
 *  13400f01   138c08 e91af161  adc ecx,dword ptr ds:[eax+ecx+0x61f11ae9>
 *  13400f08   f3:              prefix rep:                              ; superfluous prefix
 *  13400f09   90               nop
 *  13400f0a   cc               int3
 *  13400f0b   cc               int3
 */
static void SpecialPSPHookShade(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  LPCSTR text = LPCSTR(eax + hp->user_value);
  if (*text) {
    *data = (DWORD)text;
    *len = ::strlen(text);
  }
}

bool InsertShadePSPHook()
{
  ConsoleOutput("vnreng: Shade PSP: enter");
  // TODO: Query MEM_Mapped at runtime
  // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366902%28v=vs.85%29.aspx
  enum : DWORD { StartAddress = 0x13390000, StopAddress = 0x13490000 };

  const BYTE bytes[] =  {
    0xcc,                           // 13400e12   cc               int3
    0xcc,                           // 13400e13   cc               int3
    0x77, 0x0f,                     // 13400e14   77 0f            ja short 13400e25
    0xc7,0x05, XX8,                 // 13400e16   c705 a8aa1001 08>mov dword ptr ds:[0x110aaa8],0x88c1308
    0xe9, XX4,                      // 13400e20  -e9 dff161f3      jmp 06a20004
    0x8b,0x35, XX4,                 // 13400e25   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
    0x81,0xc6, 0x01,0x00,0x00,0x00, // 13400e2b   81c6 01000000    add esi,0x1
    0x8b,0x05, XX4,                 // 13400e31   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13400e37   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xb6,0xb8, XX4,            // 13400e3d   0fb6b8 00004007  movzx edi,byte ptr ds:[eax+0x7400000] ; jichi: the data is in [eax+0x7400000]
    0x8b,0x2d, XX4,                 // 13400e44   8b2d 78a71001    mov ebp,dword ptr ds:[0x110a778]
    0x8d,0x6d, 0x01,                // 13400e4a   8d6d 01          lea ebp,dword ptr ss:[ebp+0x1]
    0x81,0xff, 0x00,0x00,0x00,0x00  // 13400e4d   81ff 00000000    cmp edi,0x0
  };
  enum{ memory_offset = 3 };
  enum { hook_offset = 0x13400e3d - 0x13400e12 };

  ULONG addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Shade PSP: failed");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset);
    hp.text_fun = SpecialPSPHookShade;
    hp.type = USING_STRING;
    ConsoleOutput("vnreng: Shade PSP: INSERT");

    // CHECKPOINT 7/14/2014: This would crash vnrcli
    // I do not have permission to modify the JIT code region?
    NewHook(hp, L"Shade PSP");
  }

  //DWORD peek = 0x13400e14;
  //ITH_GROWL_DWORD(*(BYTE *)peek); // supposed to be 0x77 ja
  ConsoleOutput("vnreng: Shade PSP: leave");
  return addr;
}

#endif // 0

#if 0 // jichi 7/17/2014: Disabled as there are so many text threads
/** jichi 7/17/2014 alternative Alchemist hook
 *
 *  Sample game: your diary+ (moe-ydp.iso)
 *  The debugging method is the same as Alchemist1.
 *
 *  It seems that hooks found in Alchemist games
 *  also exist in other games.
 *
 *  This function is executed in a looped.
 *
 *  13400e12   cc               int3
 *  13400e13   cc               int3
 *  13400e14   77 0f            ja short 13400e25
 *  13400e16   c705 a8aa1001 84>mov dword ptr ds:[0x110aaa8],0x8931084
 *  13400e20  -e9 dff148f0      jmp 03890004
 *  13400e25   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
 *  13400e2b   81e0 ffffff3f    and eax,0x3fffffff
 *  13400e31   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
 *  13400e38   8b3d 78a71001    mov edi,dword ptr ds:[0x110a778]
 *  13400e3e   81fe 00000000    cmp esi,0x0
 *  13400e44   893d 7ca71001    mov dword ptr ds:[0x110a77c],edi
 *  13400e4a   8935 80a71001    mov dword ptr ds:[0x110a780],esi
 *  13400e50   0f85 16000000    jnz 13400e6c
 *  13400e56   832d c4aa1001 03 sub dword ptr ds:[0x110aac4],0x3
 *  13400e5d   e9 16010000      jmp 13400f78
 *  13400e62   01a0 109308e9    add dword ptr ds:[eax+0xe9089310],esp
 *  13400e68   b7 f1            mov bh,0xf1
 *  13400e6a   48               dec eax
 *  13400e6b   f0:832d c4aa1001>lock sub dword ptr ds:[0x110aac4],0x3    ; lock prefix
 *  13400e73   e9 0c000000      jmp 13400e84
 *  13400e78   0190 109308e9    add dword ptr ds:[eax+0xe9089310],edx
 *  13400e7e   a1 f148f090      mov eax,dword ptr ds:[0x90f048f1]
 *  13400e83   cc               int3
 *  13400e84   77 0f            ja short 13400e95
 *  13400e86   c705 a8aa1001 90>mov dword ptr ds:[0x110aaa8],0x8931090
 *  13400e90  -e9 6ff148f0      jmp 03890004
 *  13400e95   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
 *  13400e9b   8d76 01          lea esi,dword ptr ds:[esi+0x1]
 *  13400e9e   8bc6             mov eax,esi
 *  13400ea0   81e0 ffffff3f    and eax,0x3fffffff
 *  13400ea6   0fbeb8 00004007  movsx edi,byte ptr ds:[eax+0x7400000]
 *  13400ead   81ff 00000000    cmp edi,0x0
 *  13400eb3   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  13400eb9   893d 80a71001    mov dword ptr ds:[0x110a780],edi
 *  13400ebf   0f84 25000000    je 13400eea
 *  13400ec5   8b35 78a71001    mov esi,dword ptr ds:[0x110a778]
 *  13400ecb   8d76 01          lea esi,dword ptr ds:[esi+0x1]
 *  13400ece   8935 78a71001    mov dword ptr ds:[0x110a778],esi
 *  13400ed4   832d c4aa1001 04 sub dword ptr ds:[0x110aac4],0x4
 *  13400edb   e9 24000000      jmp 13400f04
 *  13400ee0   019410 9308e939  add dword ptr ds:[eax+edx+0x39e90893],ed>
 *  13400ee7   f1               int1
 *  13400ee8   48               dec eax
 *  13400ee9   f0:832d c4aa1001>lock sub dword ptr ds:[0x110aac4],0x4    ; lock prefix
 *  13400ef1   e9 82000000      jmp 13400f78
 *  13400ef6   01a0 109308e9    add dword ptr ds:[eax+0xe9089310],esp
 *  13400efc   23f1             and esi,ecx
 *  13400efe   48               dec eax
 *  13400eff   f0:90            lock nop                                 ; lock prefix is not allowed
 *  13400f01   cc               int3
 *  13400f02   cc               int3
 */
// jichi 7/17/2014: Why this function is exactly the same as SpecialPSPHookImageepoch?
static void SpecialPSPHookAlchemist3(DWORD esp_base, HookParam *hp, BYTE, DWORD *data, DWORD *split, DWORD *len)
{
  DWORD eax = regof(eax, esp_base);
  DWORD text = eax + hp->user_value;
  static DWORD lasttext;
  if (text != lasttext && *(LPCSTR)text) {
    *data = lasttext = text;
    *len = ::strlen((LPCSTR)text);
    *split = regof(ecx, esp_base); // use ecx "this" as split value?
  }
}
bool InsertAlchemist3PSPHook()
{
  ConsoleOutput("vnreng: Alchemist3 PSP: enter");
  const BYTE bytes[] =  {
    //0xcc,                         // 13400e12   cc               int3
    //0xcc,                         // 13400e13   cc               int3
    0x77, 0x0f,                     // 13400e14   77 0f            ja short 13400e25
    0xc7,0x05, XX8,                 // 13400e16   c705 a8aa1001 84>mov dword ptr ds:[0x110aaa8],0x8931084
    0xe9, XX4,                      // 13400e20  -e9 dff148f0      jmp 03890004
    0x8b,0x05, XX4,                 // 13400e25   8b05 78a71001    mov eax,dword ptr ds:[0x110a778]
    0x81,0xe0, 0xff,0xff,0xff,0x3f, // 13400e2b   81e0 ffffff3f    and eax,0x3fffffff
    0x0f,0xbe,0xb0, XX4,            // 13400e31   0fbeb0 00004007  movsx esi,byte ptr ds:[eax+0x7400000] ; jichi: hook here
    0x8b,0x3d, XX4,                 // 13400e38   8b3d 78a71001    mov edi,dword ptr ds:[0x110a778]
    0x81,0xfe, 0x00,0x00,0x00,0x00, // 13400e3e   81fe 00000000    cmp esi,0x0
    0x89,0x3d, XX4,                 // 13400e44   893d 7ca71001    mov dword ptr ds:[0x110a77c],edi
    0x89,0x35, XX4,                 // 13400e4a   8935 80a71001    mov dword ptr ds:[0x110a780],esi
    0x0f,0x85 //, 16000000          // 13400e50   0f85 16000000    jnz 13400e6c
  };
  enum { memory_offset = 3 };
  enum { hook_offset = 0x13407711 - 0x134076f4 };

  DWORD addr = SafeMatchBytesInPSPMemory(bytes, sizeof(bytes));
  if (!addr)
    ConsoleOutput("vnreng: Alchemist3 PSP: pattern not found");
  else {
    HookParam hp = {};
    hp.addr = addr + hook_offset;
    hp.user_value = *(DWORD *)(hp.addr + memory_offset); // use module to pass membase
    hp.text_fun = SpecialPSPHookAlchemist3;
    hp.type = USING_STRING|NO_CONTEXT; // no context is needed to get rid of variant retaddr
    ConsoleOutput("vnreng: Alchemist3 PSP: INSERT");
    NewHook(hp, L"Alchemist3 PSP");
  }

  ConsoleOutput("vnreng: Alchemist3 PSP: leave");
  return addr;
}
#endif // 0


#if 0 // jichi 4/21/2014: Disabled as this does not work before mono.dll is loaded

static HMODULE WaitForModuleReady(const char *name, int retryCount = 100, int sleepInterval = 100) // retry for 10 seconds
{
  for (int i = 0; i < retryCount; i++) {
    if (HMODULE h = ::GetModuleHandleA(name))
      return h;
    ::Sleep(sleepInterval);
  }
  return nullptr;
}

/**
 *  jichi 4/21/2014: Mono (Unity3D)
 *  See (ok123): http://sakuradite.com/topic/214
 *  Pattern: 33DB66390175
 *
 *  FIXME: This approach won't work before mono is loaded into the memory.
 *
 *  Example: /HWN-8*0:3C@ mono.dll search 33DB66390175
 *  - length_offset: 1
 *  - module: 1690566707 = 0x64c40033
 *  - off: 4294967284 = 0xfffffff4 = -0xc
 *  - split: 60 = 0x3c
 *  - type: 1114 = 0x45a
 *
 *  Function starts:
 *  1003b818  /$ 55             push ebp
 *  1003b819  |. 8bec           mov ebp,esp
 *  1003b81b  |. 51             push ecx
 *  1003b81c  |. 807d 10 00     cmp byte ptr ss:[ebp+0x10],0x0
 *  1003b820  |. 8b50 08        mov edx,dword ptr ds:[eax+0x8]
 *  1003b823  |. 53             push ebx
 *  1003b824  |. 8b5d 08        mov ebx,dword ptr ss:[ebp+0x8]
 *  1003b827  |. 56             push esi
 *  1003b828  |. 8b75 0c        mov esi,dword ptr ss:[ebp+0xc]
 *  1003b82b  |. 57             push edi
 *  1003b82c  |. 8d78 0c        lea edi,dword ptr ds:[eax+0xc]
 *  1003b82f  |. 897d 08        mov dword ptr ss:[ebp+0x8],edi
 *  1003b832  |. 74 44          je short mono.1003b878
 *  1003b834  |. 2bf2           sub esi,edx
 *  1003b836  |. 03f1           add esi,ecx
 *  1003b838  |. 894d 10        mov dword ptr ss:[ebp+0x10],ecx
 *  1003b83b  |. 8975 08        mov dword ptr ss:[ebp+0x8],esi
 *  1003b83e  |. 3bce           cmp ecx,esi
 *  1003b840  |. 7f 67          jg short mono.1003b8a9
 *  1003b842  |. 8d4c4b 0c      lea ecx,dword ptr ds:[ebx+ecx*2+0xc]
 *  1003b846  |> 0fb707         /movzx eax,word ptr ds:[edi]
 *  1003b849  |. 33db           |xor ebx,ebx    ; jichi hook here
 *  1003b84b  |. 66:3901        |cmp word ptr ds:[ecx],ax
 *  1003b84e  |. 75 16          |jnz short mono.1003b866
 *  1003b850  |. 8bf1           |mov esi,ecx
 *  1003b852  |> 43             |/inc ebx
 *  1003b853  |. 83c6 02        ||add esi,0x2
 *  1003b856  |. 3bda           ||cmp ebx,edx
 *  1003b858  |. 74 19          ||je short mono.1003b873
 *  1003b85a  |. 66:8b06        ||mov ax,word ptr ds:[esi]
 *  1003b85d  |. 66:3b045f      ||cmp ax,word ptr ds:[edi+ebx*2]
 *  1003b861  |.^74 ef          |\je short mono.1003b852
 *  1003b863  |. 8b75 08        |mov esi,dword ptr ss:[ebp+0x8]
 *  1003b866  |> ff45 10        |inc dword ptr ss:[ebp+0x10]
 *  1003b869  |. 83c1 02        |add ecx,0x2
 *  1003b86c  |. 3975 10        |cmp dword ptr ss:[ebp+0x10],esi
 *  1003b86f  |.^7e d5          \jle short mono.1003b846
 */
bool InsertMonoHook()
{
  enum { module = 0x64c40033 }; // hash of "mono.dll"
  DWORD base = Util::FindModuleBase(module);
  if (!base && WaitForModuleReady("mono.dll"))
    base = Util::FindModuleBase(module);

  if (!base) {
    ConsoleOutput("vnreng:Mono: module not found");
    return false;
  }

  // Instruction pattern: 90FF503C83C4208B45EC
  const BYTE ins[] = {
    0x33,0xdb,      // 1003b849  |. 33db           |xor ebx,ebx    ; jichi hook here
    0x66,0x39,0x01, // 1003b84b  |. 66:3901        |cmp word ptr ds:[ecx],ax
    0x75 //,0x16    // 1003b84e  |. 75 16          |jnz short mono.1003b866
  };
  enum { hook_offset = 0 }; // no offset
  enum { range = 0x50000 }; // larger than relative addresses = 0x3b849
  ULONG reladdr = SearchPattern(base, range, ins, sizeof(ins));
  //reladdr = 0x3b849;
  ITH_GROWL(reladdr);
  if (!reladdr) {
    ConsoleOutput("vnreng:Mono: pattern not found");
    return false;
  }

  HookParam hp = {};
  hp.addr = base + reladdr + hook_offset;
  //hp.module = module;
  hp.length_offset = 1;
  hp.off = -0xc;
  hp.split = 0x3c;
  //hp.type = NO_CONTEXT|USING_SPLIT|MODULE_OFFSET|USING_UNICODE|DATA_INDIRECT; // 0x45a;
  hp.type = NO_CONTEXT|USING_SPLIT|USING_UNICODE|DATA_INDIRECT;

  ConsoleOutput("vnreng: INSERT Mono");
  NewHook(hp, L"Mono");
  return true;
}
#endif // 0

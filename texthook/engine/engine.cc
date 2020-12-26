// engine.cc
// 8/9/2013 jichi
// Branch: ITH_Engine/engine.cpp, revision 133

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
# pragma warning (disable:4819)
#endif // _MSC_VER

#define _SCL_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include "engine/engine.h"
#include "engine/match.h"
#include "util/util.h"
#include "main.h"
#include "texthook.h"
#include "engine/mono/funcinfo.h"
#include "engine/ppsspp/funcinfo.h"
#include "ithsys/ithsys.h"
#include "memdbg/memsearch.h"
#include "disasm/disasm.h"
#include "cpputil/cppcstring.h"
#include "mono/monoobject.h"
#include "const.h"
#include "native/pchooks.h"
//#include <boost/foreach.hpp>
#include <cstdio>
#include <string>

// jichi 375/2014: Add offset of pusha/pushad
// http://faydoc.tripod.com/cpu/pushad.htm
// http://agth.wikia.com/wiki/Cheat_Engine_AGTH_Tutorial
//
// Warning: The offset in ITH has -4 offset comparing to pusha and AGTH
enum pusha_off
{
    pusha_eax_off = -0x4,
    pusha_ecx_off = -0x8,
    pusha_edx_off = -0xc,
    pusha_ebx_off = -0x10,
    pusha_esp_off = -0x14,
    pusha_ebp_off = -0x18,
    pusha_esi_off = -0x1c,
    pusha_edi_off = -0x20,
    pusha_off = -0x24 // pushad offset
};

// jichi 7/6/2014: read esp_base
#define retof(esp_base)         *(DWORD *)(esp_base) // return address
#define regof(name, esp_base)   *(DWORD *)((esp_base) + pusha_##name##_off - 4)
#define argof(count, esp_base)  *(DWORD *)((esp_base) + 4 * (count)) // starts from 1 instead of 0

//#define ConsoleOutput(...)  (void)0     // jichi 8/18/2013: I don't need ConsoleOutput

//#define DEBUG "engine.h"

enum { VNR_TEXT_CAPACITY = 1500 }; // estimated max number of bytes allowed in VNR, slightly larger than VNR's text limit (1000)


namespace { // unnamed helpers

    template <void* funcA, void* funcW, int depth = 100>
    bool StackSearchingTrigger(LPVOID funcAddr, DWORD, DWORD stack)
    {
        bool ret = false;
        if (funcAddr != funcA && funcAddr != funcW) return false;
        for (int i = 0; i < depth; ++i)
        {
            // Address of text is somewhere on stack in call to func. Search for it.
            DWORD addr = *((DWORD*)stack + i);
            //ConsoleOutput(std::to_string((DWORD)*addr).c_str());
            if (IthGetMemoryRange((void*)addr, nullptr, nullptr))
            {
                if (strlen((char*)addr) > 9)
                {
                    HookParam hp = {};
                    hp.type = DIRECT_READ;
                    if (funcAddr == funcW) hp.type |= USING_UNICODE;
                    hp.address = addr;
                    ConsoleOutput("Textractor: triggered: adding dynamic reader");
                    NewHook(hp, "READ");
                    ret = true;
                }
            };
        }
        return ret;
    }

    int PPSSPP_VERSION[4] = { 0, 9, 8, 0 }; // 0.9.8 by default

    enum : DWORD {
        PPSSPP_MEMORY_SEARCH_STEP_98 = 0x01000000
        , PPSSPP_MEMORY_SEARCH_STEP_99 = 0x00050000
        //, step = 0x1000 // step  must be at least 0x1000 (offset in SearchPattern)
        //, step = 0x00010000 // crash otoboku PSP on 0.9.9 since 5pb is wrongly inserted
    };

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

    // jichi 7/17/2014: Search mapped memory for emulators
    ULONG _SafeMatchBytesInMappedMemory(LPCVOID pattern, DWORD patternSize, BYTE wildcard,
        ULONG start, ULONG stop, ULONG step)
    {
        for (ULONG i = start; i < stop; i += step) // + patternSize to avoid overlap
            if (ULONG r = SafeFindBytes(pattern, patternSize, i, i + step + patternSize + 1))
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
    LPCSTR reverse_search_begin(const char* s, int maxsize = VNR_TEXT_CAPACITY)
    {
        if (*s)
            for (int i = 0; i < maxsize; i++, s--)
                if (!*s)
                    return s + 1;
        return nullptr;
    }

    bool all_ascii(const char* s, int maxsize = VNR_TEXT_CAPACITY)
    {
        if (s)
            for (int i = 0; i < maxsize && *s; i++, s++)
                if ((BYTE)*s > 127) // unsigned char
                    return false;
        return true;
    }

    bool all_ascii(const wchar_t* s, int maxsize = VNR_TEXT_CAPACITY)
    {
        if (s)
            for (int i = 0; i < maxsize && *s; i++, s++)
                if (*s > 127) // unsigned char
                    return false;
        return true;
    }

    // String filters

    void CharReplacer(char* str, size_t* size, char fr, char to)
    {
        size_t len = *size;
        for (size_t i = 0; i < len; i++)
            if (str[i] == fr)
                str[i] = to;
    }

    void WideCharReplacer(wchar_t* str, size_t* size, wchar_t fr, wchar_t to)
    {
        size_t len = *size / 2;
        for (size_t i = 0; i < len; i++)
            if (str[i] == fr)
                str[i] = to;
    }

    void CharFilter(char* str, size_t* size, char ch)
    {
        size_t len = *size,
            curlen;
        for (char* cur = (char*)::memchr(str, ch, len);
            (cur && --len && (curlen = len - (cur - str)));
            cur = (char*)::memchr(cur, ch, curlen))
            ::memmove(cur, cur + 1, curlen);
        *size = len;
    }

    void WideCharFilter(wchar_t* str, size_t* size, wchar_t ch)
    {
        size_t len = *size / 2,
            curlen;
        for (wchar_t* cur = cpp_wcsnchr(str, ch, len);
            (cur && --len && (curlen = len - (cur - str)));
            cur = cpp_wcsnchr(cur, ch, curlen))
            ::memmove(cur, cur + 1, 2 * curlen);
        *size = len * 2;
    }

    void CharsFilter(char* str, size_t* size, const char* chars)
    {
        size_t len = *size,
            curlen;
        for (char* cur = cpp_strnpbrk(str, chars, len);
            (cur && --len && (curlen = len - (cur - str)));
            cur = cpp_strnpbrk(cur, chars, curlen))
            ::memmove(cur, cur + 1, curlen);
        *size = len;
    }

    void WideCharsFilter(wchar_t* str, size_t* size, const wchar_t* chars)
    {
        size_t len = *size / 2,
            curlen;
        for (wchar_t* cur = cpp_wcsnpbrk(str, chars, len);
            (cur && --len && (curlen = len - (cur - str)));
            cur = cpp_wcsnpbrk(cur, chars, curlen))
            ::memmove(cur, cur + 1, 2 * curlen);
        *size = len * 2;
    }

    void StringFilter(char* str, size_t* size, const char* remove, size_t removelen)
    {
        size_t len = *size,
            curlen;
        for (char* cur = cpp_strnstr(str, remove, len);
            (cur && (len -= removelen) && (curlen = len - (cur - str)));
            cur = cpp_strnstr(cur, remove, curlen))
            ::memmove(cur, cur + removelen, curlen);
        *size = len;
    }

    void WideStringFilter(wchar_t* str, size_t* size, const wchar_t* remove, size_t removelen)
    {
        size_t len = *size / 2,
            curlen;
        for (wchar_t* cur = cpp_wcsnstr(str, remove, len);
            (cur && (len -= removelen) && (curlen = len - (cur - str)));
            cur = cpp_wcsnstr(cur, remove, curlen))
            ::memmove(cur, cur + removelen, 2 * curlen);
        *size = len * 2;
    }

    void StringFilterBetween(char* str, size_t* size, const char* fr, size_t frlen, const char* to, size_t tolen)
    {
        size_t len = *size,
            curlen;
        for (char* cur = cpp_strnstr(str, fr, len);
            cur;
            cur = cpp_strnstr(cur, fr, curlen)) {
            curlen = (len - frlen) - (cur - str);
            auto end = cpp_strnstr(cur + frlen, to, curlen);
            if (!end)
                break;
            curlen = len - (end - str) - tolen;
            ::memmove(cur, end + tolen, curlen);
            len -= tolen + (end - cur);
        }
        *size = len;
    }

    void WideStringFilterBetween(wchar_t* str, size_t* size, const wchar_t* fr, size_t frlen, const wchar_t* to, size_t tolen)
    {
        size_t len = *size / 2,
            curlen;
        for (wchar_t* cur = cpp_wcsnstr(str, fr, len);
            cur;
            cur = cpp_wcsnstr(cur, fr, curlen)) {
            curlen = (len - frlen) - (cur - str);
            auto end = cpp_wcsnstr(cur + frlen, to, curlen);
            if (!end)
                break;
            curlen = len - (end - str) - tolen;
            ::memmove(cur, end + tolen, 2 * curlen);
            len -= tolen + (end - cur);
        }
        *size = len * 2;
    }

    void StringCharReplacer(char* str, size_t* size, const char* src, size_t srclen, char ch)
    {
        size_t len = *size,
            curlen;
        for (char* cur = cpp_strnstr(str, src, len);
            cur && len;
            cur = cpp_strnstr(cur, src, curlen)) {
            *cur++ = ch;
            len -= srclen - 1;
            curlen = len - (cur - str);
            if (curlen == 0)
                break;
            ::memmove(cur, cur + srclen - 1, curlen);
        }
        *size = len;
    }

    void WideStringCharReplacer(wchar_t* str, size_t* size, const wchar_t* src, size_t srclen, wchar_t ch)
    {
        size_t len = *size / 2,
            curlen;
        for (wchar_t* cur = cpp_wcsnstr(str, src, len);
            cur && len;
            cur = cpp_wcsnstr(cur, src, curlen)) {
            *cur++ = ch;
            len -= srclen - 1;
            curlen = len - (cur - str);
            if (curlen == 0)
                break;
            ::memmove(cur, cur + srclen, 2 * curlen);
        }
        *size = len * 2;
    }

    // NOTE: I assume srclen >= dstlen
    void StringReplacer(char* str, size_t* size, const char* src, size_t srclen, const char* dst, size_t dstlen)
    {
        size_t len = *size,
            curlen;
        for (char* cur = cpp_strnstr(str, src, len);
            cur && len;
            cur = cpp_strnstr(cur, src, curlen)) {
            ::memcpy(cur, dst, dstlen);
            cur += dstlen;
            len -= srclen - dstlen;
            curlen = len - (cur - str);
            if (curlen == 0)
                break;
            if (srclen > dstlen)
                ::memmove(cur, cur + srclen - dstlen, curlen);
        }
        *size = len;
    }

    void WideStringReplacer(wchar_t* str, size_t* size, const wchar_t* src, size_t srclen, const wchar_t* dst, size_t dstlen)
    {
        size_t len = *size / 2,
            curlen;
        for (wchar_t* cur = cpp_wcsnstr(str, src, len);
            cur && len;
            cur = cpp_wcsnstr(cur, src, curlen)) {
            ::memcpy(cur, dst, 2 * dstlen);
            cur += dstlen;
            len -= srclen - dstlen;
            curlen = len - (cur - str);
            if (curlen == 0)
                break;
            if (srclen > dstlen)
                ::memmove(cur, cur + srclen - dstlen, 2 * curlen);
        }
        *size = len * 2;
    }

    bool NewLineCharFilter(LPVOID data, DWORD* size, HookParam*, BYTE)
    {
        CharFilter(reinterpret_cast<LPSTR>(data), reinterpret_cast<size_t*>(size),
            '\n');
        return true;
    }
    bool NewLineWideCharFilter(LPVOID data, DWORD* size, HookParam*, BYTE)
    {
        CharFilter(reinterpret_cast<LPSTR>(data), reinterpret_cast<size_t*>(size),
            L'\n');
        return true;
    }
    bool NewLineStringFilter(LPVOID data, DWORD* size, HookParam*, BYTE)
    {
        StringFilter(reinterpret_cast<LPSTR>(data), reinterpret_cast<size_t*>(size),
            "\\n", 2);
        return true;
    }
    bool NewLineWideStringFilter(LPVOID data, DWORD* size, HookParam*, BYTE)
    {
        WideStringFilter(reinterpret_cast<LPWSTR>(data), reinterpret_cast<size_t*>(size),
            L"\\n", 2);
        return true;
    }
    bool NewLineCharToSpaceFilter(LPVOID data, DWORD* size, HookParam*, BYTE)
    {
        CharReplacer(reinterpret_cast<LPSTR>(data), reinterpret_cast<size_t*>(size), '\n', ' ');
        return true;
    }
    bool NewLineWideCharToSpaceFilter(LPVOID data, DWORD* size, HookParam*, BYTE)
    {
        WideCharReplacer(reinterpret_cast<LPWSTR>(data), reinterpret_cast<size_t*>(size), L'\n', L' ');
        return true;
    }

    // Remove every characters <= 0x1f (i.e. before space ' ') except 0xa and 0xd.
    bool IllegalCharsFilter(LPVOID data, DWORD* size, HookParam*, BYTE)
    {
        CharsFilter(reinterpret_cast<LPSTR>(data), reinterpret_cast<size_t*>(size),
            "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x12\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f");
        return true;
    }
    bool IllegalWideCharsFilter(LPVOID data, DWORD* size, HookParam*, BYTE)
    {
        WideCharsFilter(reinterpret_cast<LPWSTR>(data), reinterpret_cast<size_t*>(size),
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
    static void SpecialHookKiriKiri(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
    {
        DWORD p1 = *(DWORD*)(esp_base - 0x14),
            p2 = *(DWORD*)(esp_base - 0x18);
        if ((p1 >> 16) == (p2 >> 16)) {
            if (DWORD p3 = *(DWORD*)p1) {
                p3 += 8;
                for (p2 = p3 + 2; *(WORD*)p2; p2 += 2);
                *len = p2 - p3;
                *data = p3;
                p1 = *(DWORD*)(esp_base - 0x20);
                p1 = *(DWORD*)(p1 + 0x74);
                *split = p1 | *(DWORD*)(esp_base + 0x48);
            }
            else
                *len = 0;
        }
        else
            *len = 0;
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
            if (*(WORD*)(pt + i) == 0x15ff) { // jichi 10/20/2014: call dword ptr ds
                DWORD addr = *(DWORD*)(pt + i + 2);

                // jichi 10/20/2014: There are multiple function calls. The flag+1 one is selected.
                // i.e. KiriKiri1: The first call to GetGlyphOutlineW is selected
                //      KiriKiri2: The second call to GetTextExtentPoint32W is selected
                if (addr >= pt && addr <= pt + size - 4
                    && *(DWORD*)addr == fun)
                    t++;
                if (t == flag + 1)  // We find call to GetGlyphOutlineW or GetTextExtentPoint32W.
                  //swprintf(str, L"CALL addr:0x%.8X",i+pt);
                  //ConsoleOutput(str);
                    for (DWORD j = i; j > i - StartAddress; j--)
                        if (((*(DWORD*)(pt + j)) & 0xffffff) == sig) {
                            if (flag) { // We find the function entry. flag indicate 2 hooks.
                                t = 0;  // KiriKiri2, we need to find call to this function.
                                for (DWORD k = j + StartRange; k < j + StopRange; k++) // Empirical range.
                                    if (*(BYTE*)(pt + k) == 0xe8) {
                                        if (k + 5 + *(DWORD*)(pt + k + 1) == j)
                                            t++;
                                        if (t == 2) {
                                            //for (k+=pt+0x14; *(WORD*)(k)!=0xC483;k++);
                                            //swprintf(str, L"Hook addr: 0x%.8X",pt+k);
                                            //ConsoleOutput(str);
                                            HookParam hp = {};
                                            hp.address = pt + k + 0x14;
                                            hp.offset = -0x14;
                                            hp.index = -0x2;
                                            hp.split = -0xc;
                                            hp.length_offset = 1;
                                            hp.type = USING_UNICODE | NO_CONTEXT | USING_SPLIT | DATA_INDIRECT;
                                            ConsoleOutput("vnreng: INSERT KiriKiri2");
                                            NewHook(hp, "KiriKiri2");
                                            return true;
                                        }
                                    }
                            }
                            else {
                                //swprintf(str, L"Hook addr: 0x%.8X",pt+j);
                                //ConsoleOutput(str);
                                HookParam hp = {};
                                hp.address = (DWORD)pt + j;
                                hp.offset = -0x8;
                                hp.index = 0x14;
                                hp.split = -0x8;
                                hp.length_offset = 1;
                                hp.type = USING_UNICODE | DATA_INDIRECT | USING_SPLIT | SPLIT_INDIRECT;
                                ConsoleOutput("vnreng: INSERT KiriKiri1");
                                NewHook(hp, "KiriKiri1");
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
        bool k1 = FindKiriKiriHook((DWORD)GetGlyphOutlineW, processStopAddress - processStartAddress, processStartAddress, 0), // KiriKiri1
            k2 = FindKiriKiriHook((DWORD)GetTextExtentPoint32W, processStopAddress - processStartAddress, processStartAddress, 1); // KiriKiri2
       //RegisterEngineType(ENGINE_KIRIKIRI);
        if (k1 && k2) {
            ConsoleOutput("vnreng:KiriKiri1: disable GDI hooks");

        }
        return k1 || k2;
    }

    /** 10/20/2014 jichi: KAGParser
     *  Sample game: [141128] Venus Blood -HYPNO- ヴィーナスブラッ�・ヒュプノ 体験版
     *
     *  drawText and drawGlyph seem to be the right function to look at.
     *  However, the latest source code does not match VenusBlood.
     *
     *  Debug method:
     *  Pre-compute: hexstr 視界のきかな�utf16, got: 96894c756e304d304b306a304430
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
     *  とな�KAGParserEx.dll
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

        bool KAGParserFilter(LPVOID data, DWORD* size, HookParam*, BYTE)
        {
            WideStringFilter(reinterpret_cast<LPWSTR>(data), reinterpret_cast<size_t*>(size), L"[r]", 3);
            return true;
        }

        void SpecialHookKAGParser(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
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

        void SpecialHookKAGParserEx(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
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
        ULONG processStartAddress, processStopAddress;
        if (!NtInspect::getModuleMemoryRange(L"KAGParser.dll", &startAddress, &stopAddress)) {
            ConsoleOutput("vnreng:KAGParser: failed to get memory range");
            return false;
        }
        const wchar_t* patternString = L"[r]";
        const size_t patternStringSize = ::wcslen(patternString) * 2;
        ULONG addr = MemDbg::findBytes(patternString, patternStringSize, processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:KAGParser: [r] global string not found");
            return false;
        }
        // Find where it is used as function parameter
        addr = MemDbg::findPushAddress(addr, processStartAddress, processStopAddress);
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
        hp.address = addr;
        hp.text_fun = SpecialHookKAGParser;
        hp.filter_fun = KAGParserFilter;
        hp.type = USING_UNICODE | FIXING_SPLIT | NO_CONTEXT; // Fix the split value to merge all threads
        ConsoleOutput("vnreng: INSERT KAGParser");
        NewHook(hp, "KAGParser");
        return true;
    }
    bool InsertKAGParserExHook()
    {
        ULONG processStartAddress, processStopAddress;
        if (!NtInspect::getModuleMemoryRange(L"KAGParserEx.dll", &startAddress, &stopAddress)) {
            ConsoleOutput("vnreng:KAGParserEx: failed to get memory range");
            return false;
        }
        const wchar_t* patternString = L"[r]";
        const size_t patternStringSize = ::wcslen(patternString) * 2;
        ULONG addr = MemDbg::findBytes(patternString, patternStringSize, processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:KAGParserEx: [r] global string not found");
            return false;
        }
        // Find where it is used as function parameter
        addr = MemDbg::findPushAddress(addr, processStartAddress, processStopAddress);
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
        hp.address = addr;
        hp.text_fun = SpecialHookKAGParserEx;
        hp.filter_fun = KAGParserFilter;
        hp.type = USING_UNICODE | FIXING_SPLIT | NO_CONTEXT; // Fix the split value to merge all threads
        ConsoleOutput("vnreng: INSERT KAGParserEx");
        NewHook(hp, "KAGParserEx");
        return true;
    }
#endif // 0

    /** 10/24/2014 jichi: New KiriKiri hook
     *  Sample game: [141128] Venus Blood -HYPNO- ヴィーナスブラッ�・ヒュプノ 体験版
     *
     *  This engine will hook to the caller of caller of the first GetGlyphOutlineW (totally three).
     *  The logic is quite similar to KiriKiri1 except it backtrack twice to get the function call.
     *
     *  1/31/2015: If the game no longer invoke GDI functions by default, one way to find the hook
     *  is to click the フォン�in the menu to force triggering GetGlyphOutlineW function.
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
     *  Since サノバウィッ� (150226), KiriKiriZ no longer invokes GetGlyphOutlineW.
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
     *  Here's the hooked function in サノバウィッ� (150226).
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
     *  The new hooked function in サノバウィッ� is as follows.
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
            hp.address = addr;
            hp.offset = pusha_ecx_off - 4;
            hp.split = hp.offset;    // the same logic but diff value as KiriKiri1, use [ecx] as split
            hp.index = 0x14;        // the same as KiriKiri1
            hp.length_offset = 1; // the same as KiriKiri1
            hp.type = USING_UNICODE | DATA_INDIRECT | USING_SPLIT | SPLIT_INDIRECT;
            //hp.filter_fun = NewLineWideCharFilter;
            ConsoleOutput("vnreng: INSERT KiriKiriZ");
            NewHook(hp, "KiriKiriZ");

            ConsoleOutput("vnreng:KiriKiriZ: disable GDI hooks");

        }

        bool KiriKiriZHook1(DWORD esp_base, HookParam*)
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
            ULONG addr = MemDbg::findCallerAddressAfterInt3((DWORD)::GetGlyphOutlineW, processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("vnreng:KiriKiriZ1: could not find caller of GetGlyphOutlineW");
                return false;
            }

            HookParam hp = {};
            hp.address = addr;
            hp.type = HOOK_EMPTY;
            hp.hook_fun = KiriKiriZHook1;
            ConsoleOutput("vnreng: INSERT KiriKiriZ1 empty hook");
            NewHook(hp, "KiriKiriZ Hook");
            return true;
        }


        // jichi 1/30/2015: Add KiriKiriZ2 for サノバウィッ�
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
            ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
            //GROWL_DWORD(addr);
            if (!addr) {
                ConsoleOutput("vnreng:KiriKiriZ2: pattern not found");
                return false;
            }

            // 012280e0   55               push ebp
            // 012280e1   8bec             mov ebp,esp
            addr = MemDbg::findEnclosingAlignedFunction(addr, 0x100); // 0x0122812f-0x012280e0 = 0x4F
            enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
            if (!addr || *(BYTE*)addr != push_ebp) {
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
    {
        return InsertKiriKiriZHook2() || InsertKiriKiriZHook1();
    }

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
                if ((*(WORD*)(pt + j)) == sig) { // Fun entry 1.
                  //swprintf(str, L"Entry 1: 0x%.8X",pt+j);
                  //ConsoleOutput(str);
                    for (DWORD k = i + 0x100; k < i + 0x800; k++)
                        if (*(BYTE*)(pt + k) == 0xe8)
                            if (k + 5 + *(DWORD*)(pt + k + 1) == j) { // Find call to fun1.
                              //swprintf(str, L"CALL to entry 1: 0x%.8X",pt+k);
                              //ConsoleOutput(str);
                                for (DWORD l = k; l > k - 0x100; l--)
                                    if ((*(WORD*)(pt + l)) == 0xec83) { // Fun entry 2.
                                      //swprintf(str, L"Entry 2(final): 0x%.8X",pt+l);
                                      //ConsoleOutput(str);
                                        HookParam hp = {};
                                        hp.address = (DWORD)pt + l;
                                        hp.offset = 0x8;
                                        hp.split = -0x18;
                                        hp.length_offset = 1;
                                        hp.type = BIG_ENDIAN | USING_SPLIT;
                                        ConsoleOutput("vnreng:INSERT DynamicBGI");
                                        NewHook(hp, "BGI");
                                        return true;
                                    }
                            }
                }
            ConsoleOutput("vnreng:DynamicBGI: failed");
            return false;
        }
        bool InsertBGIDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
        {
            if (addr != TextOutA && addr != TextOutW) {
                //ConsoleOutput("vnreng:DynamicBGI: failed");
                return false;
            }

            DWORD i = *(DWORD*)(stack + 4) - processStartAddress;
            return FindBGIHook(i, processStopAddress - processStartAddress, processStartAddress, 0xec83);
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
                DWORD* id;
                BYTE* ib;
            };
            HookParam hp = {};
            for (i = processStartAddress + 0x1000; i < processStopAddress; i++) {
                if (ib[0] == 0x3d) {
                    i++;
                    if (id[0] == 0xffff) { //cmp eax,0xffff
                        hp.address = SafeFindEntryAligned(i, 0x40);
                        if (hp.address) {
                            hp.offset = 0xc;
                            hp.split = -0x18;
                            hp.type = BIG_ENDIAN | USING_SPLIT;
                            hp.length_offset = 1;
                            ConsoleOutput("vnreng:INSERT BGI#1");
                            NewHook(hp, "BGI");
                            //RegisterEngineType(ENGINE_BGI);
                            return true;
                        }
                    }
                }
                if (ib[0] == 0x81 && ((ib[1] & 0xf8) == 0xf8)) {
                    i += 2;
                    if (id[0] == 0xffff) { //cmp reg,0xffff
                        hp.address = SafeFindEntryAligned(i, 0x40);
                        if (hp.address) {
                            hp.offset = 0xc;
                            hp.split = -0x18;
                            hp.type = BIG_ENDIAN | USING_SPLIT;
                            hp.length_offset = 1;
                            ConsoleOutput("vnreng: INSERT BGI#2");
                            NewHook(hp, "BGI");
                            //RegisterEngineType(ENGINE_BGI);
                            return true;
                        }
                    }
                }
            }
            //ConsoleOutput("Unknown BGI engine.");

            //ConsoleOutput("Probably BGI. Wait for text.");
            //SwitchTrigger(true);
            //trigger_fun=InsertBGIDynamicHook;
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
         *
         *  1/1/2016
         *  コドモノアソビ trial
         *
         *  00A64259   CC               INT3
         *  00A6425A   CC               INT3
         *  00A6425B   CC               INT3
         *  00A6425C   CC               INT3
         *  00A6425D   CC               INT3
         *  00A6425E   CC               INT3
         *  00A6425F   CC               INT3
         *  00A64260   55               PUSH EBP
         *  00A64261   8BEC             MOV EBP,ESP
         *  00A64263   83E4 F8          AND ESP,0xFFFFFFF8
         *  00A64266   6A FF            PUSH -0x1
         *  00A64268   68 D610B000      PUSH .00B010D6
         *  00A6426D   64:A1 00000000   MOV EAX,DWORD PTR FS:[0]
         *  00A64273   50               PUSH EAX
         *  00A64274   81EC 40090000    SUB ESP,0x940
         *  00A6427A   A1 2417B200      MOV EAX,DWORD PTR DS:[0xB21724]
         *  00A6427F   33C4             XOR EAX,ESP
         *  00A64281   898424 38090000  MOV DWORD PTR SS:[ESP+0x938],EAX
         *  00A64288   53               PUSH EBX
         *  00A64289   56               PUSH ESI
         *  00A6428A   57               PUSH EDI
         *  00A6428B   A1 2417B200      MOV EAX,DWORD PTR DS:[0xB21724]
         *  00A64290   33C4             XOR EAX,ESP
         *  00A64292   50               PUSH EAX
         *  00A64293   8D8424 50090000  LEA EAX,DWORD PTR SS:[ESP+0x950]
         *  00A6429A   64:A3 00000000   MOV DWORD PTR FS:[0],EAX
         *  00A642A0   8B45 08          MOV EAX,DWORD PTR SS:[EBP+0x8]
         *  00A642A3   8B7D 0C          MOV EDI,DWORD PTR SS:[EBP+0xC]
         *  00A642A6   8B5D 30          MOV EBX,DWORD PTR SS:[EBP+0x30]
         *  00A642A9   894424 50        MOV DWORD PTR SS:[ESP+0x50],EAX
         *  00A642AD   8B45 14          MOV EAX,DWORD PTR SS:[EBP+0x14]
         *  00A642B0   894C24 74        MOV DWORD PTR SS:[ESP+0x74],ECX
         *  00A642B4   8B0D A024B800    MOV ECX,DWORD PTR DS:[0xB824A0]
         *  00A642BA   894424 4C        MOV DWORD PTR SS:[ESP+0x4C],EAX
         *  00A642BE   899424 B8000000  MOV DWORD PTR SS:[ESP+0xB8],EDX
         *  00A642C5   8B55 20          MOV EDX,DWORD PTR SS:[EBP+0x20]
         *  00A642C8   51               PUSH ECX
         *  00A642C9   8D8424 14020000  LEA EAX,DWORD PTR SS:[ESP+0x214]
         *  00A642D0   897C24 2C        MOV DWORD PTR SS:[ESP+0x2C],EDI
         *  00A642D4   899C24 88000000  MOV DWORD PTR SS:[ESP+0x88],EBX
         *  00A642DB   E8 504CFDFF      CALL .00A38F30
         *  00A642E0   33C9             XOR ECX,ECX
         *  00A642E2   898424 F8000000  MOV DWORD PTR SS:[ESP+0xF8],EAX
         *  00A642E9   3BC1             CMP EAX,ECX
         *  00A642EB   0F84 391C0000    JE .00A65F2A
         *  00A642F1   E8 FA2A0000      CALL .00A66DF0
         *  00A642F6   E8 252D0000      CALL .00A67020
         *  00A642FB   898424 FC000000  MOV DWORD PTR SS:[ESP+0xFC],EAX
         *  00A64302   8A07             MOV AL,BYTE PTR DS:[EDI]
         *  00A64304   898C24 CC000000  MOV DWORD PTR SS:[ESP+0xCC],ECX
         *  00A6430B   894C24 30        MOV DWORD PTR SS:[ESP+0x30],ECX
         *  00A6430F   894C24 1C        MOV DWORD PTR SS:[ESP+0x1C],ECX
         *  00A64313   B9 01000000      MOV ECX,0x1
         *  00A64318   3C 20            CMP AL,0x20  ; jichi: pattern found here
         *  00A6431A   7D 58            JGE SHORT .00A64374
         *  00A6431C   0FBEC0           MOVSX EAX,AL
         *  00A6431F   83C0 FE          ADD EAX,-0x2
         *  00A64322   83F8 06          CMP EAX,0x6
         *  00A64325   77 4D            JA SHORT .00A64374
         *  00A64327   FF2485 505FA600  JMP DWORD PTR DS:[EAX*4+0xA65F50]
         *  00A6432E   898C24 CC000000  MOV DWORD PTR SS:[ESP+0xCC],ECX
         *  00A64335   03F9             ADD EDI,ECX
         *  00A64337   EB 37            JMP SHORT .00A64370
         *  00A64339   894C24 30        MOV DWORD PTR SS:[ESP+0x30],ECX
         *  00A6433D   03F9             ADD EDI,ECX
         *  00A6433F   EB 2F            JMP SHORT .00A64370
         *  00A64341   BA E0C1B000      MOV EDX,.00B0C1E0
         *  00A64346   EB 1A            JMP SHORT .00A64362
         *  00A64348   BA E4C1B000      MOV EDX,.00B0C1E4
         *  00A6434D   EB 13            JMP SHORT .00A64362
         *  00A6434F   BA E8C1B000      MOV EDX,.00B0C1E8
         *  00A64354   EB 0C            JMP SHORT .00A64362
         *  00A64356   BA ECC1B000      MOV EDX,.00B0C1EC
         *  00A6435B   EB 05            JMP SHORT .00A64362
         *  00A6435D   BA F0C1B000      MOV EDX,.00B0C1F0
         *  00A64362   8D7424 14        LEA ESI,DWORD PTR SS:[ESP+0x14]
         *  00A64366   894C24 1C        MOV DWORD PTR SS:[ESP+0x1C],ECX
         *  00A6436A   E8 A196FFFF      CALL .00A5DA10
         *  00A6436F   47               INC EDI
         *  00A64370   897C24 28        MOV DWORD PTR SS:[ESP+0x28],EDI
         *  00A64374   8D8424 10020000  LEA EAX,DWORD PTR SS:[ESP+0x210]
         *  00A6437B   E8 C01C0000      CALL .00A66040
         *  00A64380   837D 10 00       CMP DWORD PTR SS:[EBP+0x10],0x0
         *  00A64384   8BB424 30020000  MOV ESI,DWORD PTR SS:[ESP+0x230]
         *  00A6438B   894424 60        MOV DWORD PTR SS:[ESP+0x60],EAX
         *  00A6438F   74 12            JE SHORT .00A643A3
         *  00A64391   56               PUSH ESI
         *  00A64392   E8 C91C0000      CALL .00A66060
         *  00A64397   83C4 04          ADD ESP,0x4
         *  00A6439A   898424 C4000000  MOV DWORD PTR SS:[ESP+0xC4],EAX
         *  00A643A1   EB 0B            JMP SHORT .00A643AE
         *  00A643A3   C78424 C4000000 >MOV DWORD PTR SS:[ESP+0xC4],0x0
         *  00A643AE   8B4B 04          MOV ECX,DWORD PTR DS:[EBX+0x4]
         *  00A643B1   0FAFCE           IMUL ECX,ESI
         *  00A643B4   B8 1F85EB51      MOV EAX,0x51EB851F
         *  00A643B9   F7E9             IMUL ECX
         *  00A643BB   C1FA 05          SAR EDX,0x5
         *  00A643BE   8BCA             MOV ECX,EDX
         *  00A643C0   C1E9 1F          SHR ECX,0x1F
         *  00A643C3   03CA             ADD ECX,EDX
         *  00A643C5   898C24 94000000  MOV DWORD PTR SS:[ESP+0x94],ECX
         *  00A643CC   85C9             TEST ECX,ECX
         *  00A643D0   B9 01000000      MOV ECX,0x1
         *  ...
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
         //  LPCSTR text = (LPCSTR)*(DWORD *)(esp_base + hp->offset);
         //  if (text) {
         //    *data = (DWORD)text;
         //    *len = _bgistrlen(text);
         //  }
         //}

        bool InsertBGI2Hook()
        {
            const BYTE bytes[] = {
                // The following code does not exist in newer BGI games after BGI 1.633.0.0 (tayutama2_trial_EX)
                //0x3c, 0x20,      // 011d4d31  |. 3c 20          cmp al,0x20
                //0x7d, XX,        // 011d4d33  |. 7d 75          jge short sekachu.011d4daa ; jichi: 0x75 or 0x58
                0x0f,0xbe,0xc0,  // 011d4d35  |. 0fbec0         movsx eax,al
                0x83,0xc0, 0xfe, // 011d4d38  |. 83c0 fe        add eax,-0x2               ;  switch (cases 2..8)
                0x83,0xf8//, 0x06  // 011d4d3b  |. 83f8 06        cmp eax,0x6
                // The following code does not exist in newer BGI games after 蒼の彼方
                //0x77, 0x6a     // 011d4d3e  |. 77 6a          ja short sekachu.011d4daa
            };

            ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
            //GROWL_DWORD(reladdr);
            if (!addr) {
                ConsoleOutput("vnreng:BGI2: pattern not found");
                return false;
            }

            DWORD funaddr = MemDbg::findEnclosingAlignedFunction(addr, 0x300); // range is around 177 ~ 190

            enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
            if (!funaddr || *(BYTE*)funaddr != push_ebp) {
                ConsoleOutput("vnreng:BGI2: pattern found but the function offset is invalid");
                return false;
            }

            /* Artikash 6/14/2019: Ugh, what a mess I've dug up...
            At some point the beginning four bytes to search for were removed, but the difference below were not corrected? Or maybe they were?
            I don't have all these games so no way to confirm which (if any) are wrong.
            But the first difference (the important one since it's the one detecting offset=arg3, all others give new) seems to be four bytes off when hooking https://vndb.org/v8158
            ...but maybe it's not? Maybe I discovered a new difference?
            I think the safest option is to just add the new? difference as a case that detects offset=arg3 since either way one case will detect offset=arg3 correctly.
            And all the other cases fall through to offset=arg2.
            */
            HookParam hp = {};
            switch (funaddr - addr) {
                // for old BGI2 game, text is arg3
            case 0x34c80 - 0x34d31: // old offset
            case 0x34c50 - 0x34d05: // correction as mentioned above
                hp.offset = 4 * 3;
                break;
                // for new BGI2 game since 蒼の彼方 (2014/08), text is in arg2
            case 0x01312cd0 - 0x01312D92:
                // For newer BGI2 game since コドモノアソビ (2015/11)
            case 0x00A64260 - 0x00A6431C:
                // For latest BGI2 game since タユタマ２(2016/05) by @mireado
            case 0x00E95290 - 0x00E95349:
                // For latest BGI2 game since 千の刃濤、桃花染の皇姫 体験版  by @mireado
            case 0x00AF5640 - 0x00AF56FF:
                // For latest BGI2 game since by BGI 1.633.0.0 @mireado
            case 0x00D8A660 - 0x00D8A73A:
                hp.offset = 4 * 2;
                break;
                // Artikash 8/1/2018: Looks like it's basically always 4*2. Remove error from default case: breaks SubaHibi HD. Will figure out how to do this properly if it becomes an issue.
            default:
                ConsoleOutput("Textractor: BGI2 WARN: function-code distance unknown");
                hp.offset = 4 * 2;
                break;
            }
            hp.address = funaddr;

            // jichi 5/12/2014: Using split could distinguish name and choices. But the signature might become unstable
            hp.type = USING_STRING | USING_SPLIT;
            hp.split = 4 * 8; // pseudo arg8
            //hp.split = -0x18;

            //GROWL_DWORD2(hp.address, processStartAddress);

            ConsoleOutput("vnreng: INSERT BGI2");
            NewHook(hp, "BGI2");

            // Disable TextOutA, which is cached and hence missing characters.
            ConsoleOutput("vnreng:BGI2: disable GDI hooks");

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
         *  [ぷちけろ] コトバの消えた日 �忁�で裸にする純�調教～体験版
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
            //enum { addr_offset = 0 };
            ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
            //reladdr = 0x68e56;
            if (!addr) {
                ConsoleOutput("vnreng:BGI3: pattern not found");
                return false;
            }

            HookParam hp = {};
            hp.type = USING_STRING | USING_SPLIT;
            hp.offset = -0x20;
            hp.split = -0x8;
            hp.address = addr;

            //GROWL_DWORD2(hp.address, processStartAddress);

            ConsoleOutput("vnreng: INSERT BGI3");
            NewHook(hp, "BGI3");
            return true;
        }
#endif // 0
    } // unnamed

    // jichi 5/12/2014: BGI1 and BGI2 game can co-exist, such as 世界と世界の真ん中で
    // BGI1 can exist in both old and new games
    // BGI2 only exist in new games
    // Insert BGI2 first.
    // Artikash 6/12/2019: In newer games neither exists, but WideCharToMultiByte works, so insert that if BGI2 fails.
    bool InsertBGIHook()
    {
        return InsertBGI2Hook() || (PcHooks::hookOtherPcFunctions(), InsertBGI1Hook());
    }

    /********************************************************************************************
    Reallive hook:
      Process name is reallive.exe or reallive*.exe.
      Technique to find Reallive hook is quite different from 2 above.
      Usually Reallive engine has a font caching issue. This time we wait
      until the first call to GetGlyphOutlineA. Reallive engine usually set
      up stack frames so we can just refer to EBP to find function entry.
    ********************************************************************************************/
    /** jichi 5/13/2015
     *  RealLive does not work for 水着少女と媚薬アイス from 裸足少女
     *  012da80f   cc               int3
     *  012da810   55               push ebp    ; jichi: change to hook here
     *  012da811   8bec             mov ebp,esp
     *  012da813   83ec 10          sub esp,0x10 ; jichi: hook here by default
     *  012da816   53               push ebx
     *  012da817   56               push esi
     *  012da818   57               push edi
     *  012da819   8b7d 18          mov edi,dword ptr ss:[ebp+0x18]
     *  012da81c   81ff 5c810000    cmp edi,0x815c
     *  012da822   75 0a            jnz short reallive.012da82e
     *  012da824   c745 18 9f840000 mov dword ptr ss:[ebp+0x18],0x849f
     *  012da82b   8b7d 18          mov edi,dword ptr ss:[ebp+0x18]
     *  012da82e   b8 9041e301      mov eax,reallive.01e34190
     *  012da833   b9 18a49001      mov ecx,reallive.0190a418
     *  012da838   e8 a38d0000      call reallive.012e35e0
     *  012da83d   85c0             test eax,eax
     *  012da83f   74 14            je short reallive.012da855
     *  012da841   e8 6addffff      call reallive.012d85b0
     *  012da846   ba 9041e301      mov edx,reallive.01e34190
     *  012da84b   b8 18a49001      mov eax,reallive.0190a418
     *  012da850   e8 ab7c0000      call reallive.012e2500
     *  012da855   8d45 f0          lea eax,dword ptr ss:[ebp-0x10]
     *  012da858   50               push eax
     *  012da859   8d4d f4          lea ecx,dword ptr ss:[ebp-0xc]
     *  012da85c   51               push ecx
     *  012da85d   8d55 fc          lea edx,dword ptr ss:[ebp-0x4]
     *  012da860   52               push edx
     *  012da861   8d45 f8          lea eax,dword ptr ss:[ebp-0x8]
     *  012da864   50               push eax
     *  012da865   8bc7             mov eax,edi
     *  012da867   e8 54dfffff      call reallive.012d87c0
     *  012da86c   8bf0             mov esi,eax
     *  012da86e   83c4 10          add esp,0x10
     *  012da871   85f6             test esi,esi
     *  012da873   75 4b            jnz short reallive.012da8c0
     *  012da875   8d4d f4          lea ecx,dword ptr ss:[ebp-0xc]
     *  012da878   51               push ecx
     *  012da879   57               push edi
     *  012da87a   8d4d f0          lea ecx,dword ptr ss:[ebp-0x10]
     *  012da87d   e8 cef0ffff      call reallive.012d9950
     *  012da882   8bf0             mov esi,eax
     *  012da884   83c4 08          add esp,0x8
     *  012da887   85f6             test esi,esi
     */
    static bool InsertRealliveDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
    {
        if (addr != ::GetGlyphOutlineA)
            return false;
        // jichi 5/13/2015: Find the enclosing caller of GetGlyphOutlineA
        if (DWORD i = frame) {
            i = *(DWORD*)(i + 4);
            for (DWORD j = i; j > i - 0x100; j--)
                if (*(WORD*)j == 0xec83) { // jichi 7/26/2014: function starts
                  // 012da80f   cc               int3
                  // 012da810   55               push ebp    ; jichi: change to hook here
                  // 012da811   8bec             mov ebp,esp
                  // 012da813   83ec 10          sub esp,0x10 ; jichi: hook here by default
                    if (*(DWORD*)(j - 3) == 0x83ec8b55)
                        j -= 3;

                    HookParam hp = {};
                    hp.address = j;
                    hp.offset = 0x14;
                    hp.split = pusha_esp_off - 4; // -0x18
                    hp.length_offset = 1;
                    hp.type = BIG_ENDIAN | USING_SPLIT;
                    //GROWL_DWORD(hp.address);
                    NewHook(hp, "RealLive");
                    //RegisterEngineType(ENGINE_REALLIVE);
                    ConsoleOutput("vnreng:RealLive: disable GDI hooks");

                    return true;
                }
        }
        return true; // jichi 12/25/2013: return true
    }
    void InsertRealliveHook()
    {
        //ConsoleOutput("Probably Reallive. Wait for text.");
        ConsoleOutput("vnreng: TRIGGER Reallive");
        trigger_fun = InsertRealliveDynamicHook;
    }

    namespace { // unnamed

    /**
     *  jichi 8/17/2013:  SiglusEngine from siglusengine.exe
     *  The old hook does not work for new games.
     *  The new hook cannot recognize character names.
     *  Insert old first. As the pattern could also be found in the old engine.
     */

     /** jichi 10/25/2014: new SiglusEngine3 that can extract character name
      *
      *  Sample game: リア兂�ラスメイト孕ませ催� -- /HW-4@F67DC:SiglusEngine.exe
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
            enum { addr_offset = sizeof(bytes) - 4 };
            ULONG range = max(processStopAddress - processStartAddress, MAX_REL_ADDR);
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
            if (!addr) {
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
            hp.address = addr + addr_offset;
            hp.offset = pusha_eax_off - 4;
            hp.type = USING_UNICODE;
            hp.length_offset = 1;
            //hp.text_fun = SpecialHookSiglus3;

            ConsoleOutput("vnreng: INSERT Siglus3");
            NewHook(hp, "SiglusEngine3");

            ConsoleOutput("vnreng:Siglus3: disable GDI hooks");

            return true;
        }

        /** SiglusEngine4 5/23/2015
         *  Sample game: AngleBeats trial
         *  Alternative ATcode from EGDB:
         *  UNIKOFILTER(30),FORCEFONT(5),HOOK(SiglusEngine.exe!0x0018CF39,TRANS(EAX,UNICODE,SMSTR,ADDNULL),RETNPOS(SOURCE))
         *  Text address is [eax]
         *
         *  0042CEFD   CC               INT3
         *  0042CEFE   CC               INT3
         *  0042CEFF   CC               INT3
         *  0042CF00   55               PUSH EBP
         *  0042CF01   8BEC             MOV EBP,ESP
         *  0042CF03   51               PUSH ECX
         *  0042CF04   A1 005E8A00      MOV EAX,DWORD PTR DS:[0x8A5E00]
         *  0042CF09   53               PUSH EBX
         *  0042CF0A   56               PUSH ESI
         *  0042CF0B   57               PUSH EDI
         *  0042CF0C   8B40 10          MOV EAX,DWORD PTR DS:[EAX+0x10]
         *  0042CF0F   8BF9             MOV EDI,ECX
         *  0042CF11   33C9             XOR ECX,ECX
         *  0042CF13   C745 FC 00000000 MOV DWORD PTR SS:[EBP-0x4],0x0
         *  0042CF1A   6A FF            PUSH -0x1
         *  0042CF1C   51               PUSH ECX
         *  0042CF1D   83E8 18          SUB EAX,0x18
         *  0042CF20   C747 14 07000000 MOV DWORD PTR DS:[EDI+0x14],0x7
         *  0042CF27   C747 10 00000000 MOV DWORD PTR DS:[EDI+0x10],0x0
         *  0042CF2E   66:890F          MOV WORD PTR DS:[EDI],CX
         *  0042CF31   8BCF             MOV ECX,EDI
         *  0042CF33   50               PUSH EAX
         *  0042CF34   E8 E725F6FF      CALL .0038F520
         *  0042CF39   8B1D 005E8A00    MOV EBX,DWORD PTR DS:[0x8A5E00] ; jichi: ATcode hooked here, text sometimes in eax sometimes address in eax, size in [eax+0x16]
         *  0042CF3F   8B73 10          MOV ESI,DWORD PTR DS:[EBX+0x10]
         *  0042CF42   837E FC 08       CMP DWORD PTR DS:[ESI-0x4],0x8
         *  0042CF46   72 0B            JB SHORT .0042CF53
         *  0042CF48   FF76 E8          PUSH DWORD PTR DS:[ESI-0x18]
         *  0042CF4B   E8 EA131300      CALL .0055E33A
         *  0042CF50   83C4 04          ADD ESP,0x4
         *  0042CF53   33C0             XOR EAX,EAX
         *  0042CF55   C746 FC 07000000 MOV DWORD PTR DS:[ESI-0x4],0x7
         *  0042CF5C   C746 F8 00000000 MOV DWORD PTR DS:[ESI-0x8],0x0
         *  0042CF63   66:8946 E8       MOV WORD PTR DS:[ESI-0x18],AX
         *  0042CF67   8BC7             MOV EAX,EDI
         *  0042CF69   8343 10 E8       ADD DWORD PTR DS:[EBX+0x10],-0x18
         *  0042CF6D   5F               POP EDI
         *  0042CF6E   5E               POP ESI
         *  0042CF6F   5B               POP EBX
         *  0042CF70   8BE5             MOV ESP,EBP
         *  0042CF72   5D               POP EBP
         *  0042CF73   C3               RETN
         *  0042CF74   CC               INT3
         *  0042CF75   CC               INT3
         *  0042CF76   CC               INT3
         *  0042CF77   CC               INT3
         */
        bool Siglus4Filter(LPVOID data, DWORD* size, HookParam*, BYTE)
        {
            auto text = reinterpret_cast<LPWSTR>(data);
            auto len = reinterpret_cast<size_t*>(size);
            // Remove "NNLI"
            //if (*len > 2 && ::all_ascii(text))
            //  return false;
            //if (*len == 2 && *text == L'N')
            //  return false;
            WideStringFilter(text, len, L"NLI", 3);
            // Replace 『�(300e, 300f) with 「�(300c,300d)
            //WideCharReplacer(text, len, 0x300e, 0x300c);
            //WideCharReplacer(text, len, 0x300f, 0x300d);
            return true;
        }
        void SpecialHookSiglus4(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            //static uint64_t lastTextHash_;
            DWORD eax = regof(eax, esp_base); // text
            if (!eax || !*(const BYTE*)eax) // empty data
                return;
            DWORD size = *(DWORD*)(eax + 0x10);
            if (!size)
                return;
            if (size < 8)
                *data = eax;
            else
                *data = *(DWORD*)eax;

            // Skip all ascii characters
            if (all_ascii((LPCWSTR)*data))
                return;

            // Avoid duplication
            //LPCWSTR text = (LPCWSTR)*data;
            //auto hash = hashstr(text);
            //if (hash == lastTextHash_)
            //  return;
            //lastTextHash_ = hash;

            *len = size * 2; // UTF-16
            DWORD s0 = retof(esp_base); // use stack[0] as split
            if (s0 <= 0xff) // scenario text
                *split = FIXED_SPLIT_VALUE;
            else if (::IsBadReadPtr((LPCVOID)s0, 4))
                *split = s0;
            else {
                *split = *(DWORD*)s0; // This value is runtime dependent
                if (*split == 0x54)
                    *split = FIXED_SPLIT_VALUE * 2;
            }
            *split += argof(1, esp_base); // plus stack[1] as split
        }
        bool InsertSiglus4Hook()
        {
            const BYTE bytes[] = {
              0xc7,0x47, 0x14, 0x07,0x00,0x00,0x00,   // 0042cf20   c747 14 07000000 mov dword ptr ds:[edi+0x14],0x7
              0xc7,0x47, 0x10, 0x00,0x00,0x00,0x00,   // 0042cf27   c747 10 00000000 mov dword ptr ds:[edi+0x10],0x0
              0x66,0x89,0x0f,                         // 0042cf2e   66:890f          mov word ptr ds:[edi],cx
              0x8b,0xcf,                              // 0042cf31   8bcf             mov ecx,edi
              0x50,                                   // 0042cf33   50               push eax
              0xe8 //XX4                              // 0042cf34   e8 e725f6ff      call .0038f520
              // hook here
            };
            enum { addr_offset = sizeof(bytes) + 4 }; // +4 for the call address
            ULONG range = max(processStopAddress - processStartAddress, MAX_REL_ADDR);
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
            //ULONG addr = processStartAddress + 0x0018cf39;
            if (!addr) {
                //ConsoleOutput("Unknown SiglusEngine");
                ConsoleOutput("vnreng:Siglus4: pattern not found");
                return false;
            }

            //addr = MemDbg::findEnclosingAlignedFunction(addr, 50); // 0x002667dc - 0x002667c0 = 28
            //if (!addr) {
            //  ConsoleOutput("vnreng:Siglus3: enclosing function not found");
            //  return false;
            //}

            HookParam hp = {};
            hp.address = addr + addr_offset;
            hp.type = NO_CONTEXT | USING_UNICODE;
            hp.text_fun = SpecialHookSiglus4;
            hp.filter_fun = Siglus4Filter;
            //hp.offset = pusha_eax_off - 4;
            //hp.type = USING_UNICODE|DATA_INDIRECT|USING_SPLIT|NO_CONTEXT;
            //hp.type = USING_UNICODE|USING_SPLIT|NO_CONTEXT;
            //hp.split = pusha_edx_off - 4;

            ConsoleOutput("vnreng: INSERT Siglus4");
            NewHook(hp, "SiglusEngine4");

            ConsoleOutput("vnreng:Siglus4: disable GDI hooks");

            return true;
        }

#if 0 // not all text can be extracted
        /** jichi: 6/16/2015 Siglus4Engine for Frill games
         *  Sample game: 冺�少女
         *
         *  This function is found by tracking where the text length is modified
         *
         *  Base address: 0x070000
         *
         *  0020F51B   CC               INT3
         *  0020F51C   CC               INT3
         *  0020F51D   CC               INT3
         *  0020F51E   CC               INT3
         *  0020F51F   CC               INT3
         *  0020F520   55               PUSH EBP	; jichi: memory address in [arg1+0x4], text length in arg1
         *  0020F521   8BEC             MOV EBP,ESP
         *  0020F523   6A FF            PUSH -0x1
         *  0020F525   68 889B5900      PUSH .00599B88
         *  0020F52A   64:A1 00000000   MOV EAX,DWORD PTR FS:[0]
         *  0020F530   50               PUSH EAX
         *  0020F531   83EC 1C          SUB ESP,0x1C
         *  0020F534   53               PUSH EBX
         *  0020F535   56               PUSH ESI
         *  0020F536   57               PUSH EDI
         *  0020F537   A1 E0946500      MOV EAX,DWORD PTR DS:[0x6594E0]
         *  0020F53C   33C5             XOR EAX,EBP
         *  0020F53E   50               PUSH EAX
         *  0020F53F   8D45 F4          LEA EAX,DWORD PTR SS:[EBP-0xC]
         *  0020F542   64:A3 00000000   MOV DWORD PTR FS:[0],EAX
         *  0020F548   8BD1             MOV EDX,ECX
         *  0020F54A   8955 F0          MOV DWORD PTR SS:[EBP-0x10],EDX
         *  0020F54D   8B45 0C          MOV EAX,DWORD PTR SS:[EBP+0xC]
         *  0020F550   8B5D 10          MOV EBX,DWORD PTR SS:[EBP+0x10]
         *  0020F553   3BC3             CMP EAX,EBX
         *  0020F555   0F8D DF000000    JGE .0020F63A
         *  0020F55B   8B75 08          MOV ESI,DWORD PTR SS:[EBP+0x8]
         *  0020F55E   8D0C40           LEA ECX,DWORD PTR DS:[EAX+EAX*2]
         *  0020F561   C1E1 03          SHL ECX,0x3
         *  0020F564   2BD8             SUB EBX,EAX
         *  0020F566   894D 0C          MOV DWORD PTR SS:[EBP+0xC],ECX
         *  0020F569   8DA424 00000000  LEA ESP,DWORD PTR SS:[ESP]
         *  0020F570   8B82 A4000000    MOV EAX,DWORD PTR DS:[EDX+0xA4]
         *  0020F576   03C1             ADD EAX,ECX
         *  0020F578   C745 EC 07000000 MOV DWORD PTR SS:[EBP-0x14],0x7
         *  0020F57F   33C9             XOR ECX,ECX
         *  0020F581   C745 E8 00000000 MOV DWORD PTR SS:[EBP-0x18],0x0
         *  0020F588   6A FF            PUSH -0x1
         *  0020F58A   51               PUSH ECX
         *  0020F58B   66:894D D8       MOV WORD PTR SS:[EBP-0x28],CX
         *  0020F58F   8D4D D8          LEA ECX,DWORD PTR SS:[EBP-0x28]
         *  0020F592   50               PUSH EAX
         *  0020F593   E8 68EFF4FF      CALL .0015E500
         *  0020F598   C745 FC 00000000 MOV DWORD PTR SS:[EBP-0x4],0x0
         *  0020F59F   8BCE             MOV ECX,ESI
         *  0020F5A1   8B46 0C          MOV EAX,DWORD PTR DS:[ESI+0xC]
         *  0020F5A4   8B7D E8          MOV EDI,DWORD PTR SS:[EBP-0x18]
         *  0020F5A7   83C0 04          ADD EAX,0x4
         *  0020F5AA   50               PUSH EAX
         *  0020F5AB   E8 209DF5FF      CALL .001692D0
         *  0020F5B0   8B0E             MOV ECX,DWORD PTR DS:[ESI]
         *  0020F5B2   8D55 D8          LEA EDX,DWORD PTR SS:[EBP-0x28]
         *  0020F5B5   33C0             XOR EAX,EAX
         *  0020F5B7   3B4E 04          CMP ECX,DWORD PTR DS:[ESI+0x4]
         *  0020F5BA   0F44C8           CMOVE ECX,EAX
         *  0020F5BD   8B46 0C          MOV EAX,DWORD PTR DS:[ESI+0xC]
         *  0020F5C0   893C01           MOV DWORD PTR DS:[ECX+EAX],EDI	; jichi: text length modified here
         *  0020F5C3   8B45 E8          MOV EAX,DWORD PTR SS:[EBP-0x18]
         *  0020F5C6   8346 0C 04       ADD DWORD PTR DS:[ESI+0xC],0x4
         *  0020F5CA   8B4D D8          MOV ECX,DWORD PTR SS:[EBP-0x28]
         *  0020F5CD   8D3C00           LEA EDI,DWORD PTR DS:[EAX+EAX]
         *  0020F5D0   8B45 EC          MOV EAX,DWORD PTR SS:[EBP-0x14]
         *  0020F5D3   83F8 08          CMP EAX,0x8
         *  0020F5D6   0F43D1           CMOVNB EDX,ECX
         *  0020F5D9   8955 10          MOV DWORD PTR SS:[EBP+0x10],EDX
         *  0020F5DC   85FF             TEST EDI,EDI
         *  0020F5DE   7E 32            JLE SHORT .0020F612
         *  0020F5E0   8B46 0C          MOV EAX,DWORD PTR DS:[ESI+0xC]
         *  0020F5E3   8BCE             MOV ECX,ESI
         *  0020F5E5   03C7             ADD EAX,EDI
         *  0020F5E7   50               PUSH EAX
         *  0020F5E8   E8 E39CF5FF      CALL .001692D0
         *  0020F5ED   8B0E             MOV ECX,DWORD PTR DS:[ESI]
         *  0020F5EF   33C0             XOR EAX,EAX
         *  0020F5F1   3B4E 04          CMP ECX,DWORD PTR DS:[ESI+0x4]
         *  0020F5F4   57               PUSH EDI
         *  0020F5F5   FF75 10          PUSH DWORD PTR SS:[EBP+0x10]
         *  0020F5F8   0F44C8           CMOVE ECX,EAX
         *  0020F5FB   8B46 0C          MOV EAX,DWORD PTR DS:[ESI+0xC]
         *  0020F5FE   03C1             ADD EAX,ECX
         *  0020F600   50               PUSH EAX
         *  0020F601   E8 EA1B1200      CALL .003311F0
         *  0020F606   8B45 EC          MOV EAX,DWORD PTR SS:[EBP-0x14]
         *  0020F609   83C4 0C          ADD ESP,0xC
         *  0020F60C   017E 0C          ADD DWORD PTR DS:[ESI+0xC],EDI
         *  0020F60F   8B4D D8          MOV ECX,DWORD PTR SS:[EBP-0x28]
         *  0020F612   C745 FC FFFFFFFF MOV DWORD PTR SS:[EBP-0x4],-0x1
         *  0020F619   83F8 08          CMP EAX,0x8
         *  0020F61C   72 09            JB SHORT .0020F627
         *  0020F61E   51               PUSH ECX
         *  0020F61F   E8 A6DC1100      CALL .0032D2CA
         *  0020F624   83C4 04          ADD ESP,0x4
         *  0020F627   8B4D 0C          MOV ECX,DWORD PTR SS:[EBP+0xC]
         *  0020F62A   8B55 F0          MOV EDX,DWORD PTR SS:[EBP-0x10]
         *  0020F62D   83C1 18          ADD ECX,0x18
         *  0020F630   894D 0C          MOV DWORD PTR SS:[EBP+0xC],ECX
         *  0020F633   4B               DEC EBX
         *  0020F634  ^0F85 36FFFFFF    JNZ .0020F570
         *  0020F63A   8B4D F4          MOV ECX,DWORD PTR SS:[EBP-0xC]
         *  0020F63D   64:890D 00000000 MOV DWORD PTR FS:[0],ECX
         *  0020F644   59               POP ECX
         *  0020F645   5F               POP EDI
         *  0020F646   5E               POP ESI
         *  0020F647   5B               POP EBX
         *  0020F648   8BE5             MOV ESP,EBP
         *  0020F64A   5D               POP EBP
         *  0020F64B   C2 0C00          RETN 0xC
         *  0020F64E   CC               INT3
         *  0020F64F   CC               INT3
         */
        void SpecialHookSiglus4(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            static uint64_t lastTextHash_;
            DWORD arg1 = argof(1, esp_base); // arg1
            DWORD addr = *(DWORD*)(arg1 + 4);
            int size = *(DWORD*)addr;
            if (size <= 0 || size > VNR_TEXT_CAPACITY)
                return;
            auto text = LPWSTR(addr + 4);
            if (!text || ::IsBadWritePtr(text, size * 2) || !*text || ::wcslen(text) != size || lastTextHash_ == hashstr(text)) //  || text[size+1], skip if text's size + 1 is not empty
                return;
            lastTextHash_ = hashstr(text); // skip last repetition
            *len = size * 2;
            *data = (DWORD)text;
            *split = argof(3, esp_base); // arg3
        }
        bool InsertSiglus4Hook()
        {
            ULONG processStartAddress, processStopAddress;
            if (!FillRange(processName, &startAddress, &stopAddress)) { // need accurate stopAddress
                ConsoleOutput("vnreng:Siglus4: failed to get memory range");
                return false;
            }
            const BYTE bytes[] = {
              0x8b,0x75, 0x08, // 0020f55b   8b75 08          mov esi,dword ptr ss:[ebp+0x8]
              0x8d,0x0c,0x40,  // 0020f55e   8d0c40           lea ecx,dword ptr ds:[eax+eax*2]
              0xc1,0xe1, 0x03, // 0020f561   c1e1 03          shl ecx,0x3
              0x2b,0xd8,       // 0020f564   2bd8             sub ebx,eax
              0x89,0x4d, 0x0c  // 0020f566   894d 0c          mov dword ptr ss:[ebp+0xc],ecx

              // The following pattern is not unique, there are at least four matches
              //                        // 0020f5b7   3b4e 04     cmp ecx,dword ptr ds:[esi+0x4]
              //                        // 0020f5ba   0f44c8      cmove ecx,eax
              //0x8b,0x46, 0x0c,        // 0020f5bd   8b46 0c     mov eax,dword ptr ds:[esi+0xc]
              //0x89,0x3c,0x01,         // 0020f5c0   893c01      mov dword ptr ds:[ecx+eax],edi	; jichi: text length modified here
              //0x8b,0x45, 0xe8,        // 0020f5c3   8b45 e8     mov eax,dword ptr ss:[ebp-0x18]
              //0x83,0x46, 0x0c, 0x04,  // 0020f5c6   8346 0c 04  add dword ptr ds:[esi+0xc],0x4
              //0x8b,0x4d, 0xd8,        // 0020f5ca   8b4d d8     mov ecx,dword ptr ss:[ebp-0x28]
              //0x8d,0x3c,0x00          // 0020f5cd   8d3c00      lea edi,dword ptr ds:[eax+eax]
              //                        // 0020f5d0   8b45 ec     mov eax,dword ptr ss:[ebp-0x14]
            };
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
            if (!addr) {
                //ConsoleOutput("Unknown SiglusEngine");
                ConsoleOutput("vnreng:Siglus4: pattern not found");
                return false;
            }
            addr = MemDbg::findEnclosingAlignedFunction(addr, 0x100); // 0x0020f55b - 0x0020F520 = 59
            if (!addr) {
                ConsoleOutput("vnreng:Siglus4: enclosing function not found");
                return false;
            }

            //addr += 0x0020f64b - 0x0020f520; // hook to ret instead

            HookParam hp = {};
            hp.address = addr;
            //hp.type = USING_UNICODE;
            hp.type = NO_CONTEXT;
            hp.text_fun = SpecialHookSiglus4;
            hp.filter_fun = Siglus4Filter; // remove NLI from the game

            //GROWL_DWORD(addr);

            ConsoleOutput("vnreng: INSERT Siglus4");
            NewHook(hp, "SiglusEngine4");

            ConsoleOutput("vnreng:Siglus4: disable GDI hooks");

            return true;
        }
#endif // 0


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
         *  10/18/2014 Type2: リア兂�ラスメイト孕ませ催�
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
         *
         *  In AngleBeats, base = 0x09a0000
         *  00B6B87C   CC               INT3
         *  00B6B87D   CC               INT3
         *  00B6B87E   CC               INT3
         *  00B6B87F   CC               INT3
         *  00B6B880   55               PUSH EBP
         *  00B6B881   8BEC             MOV EBP,ESP
         *  00B6B883   6A FF            PUSH -0x1
         *  00B6B885   68 7964ED00      PUSH .00ED6479
         *  00B6B88A   64:A1 00000000   MOV EAX,DWORD PTR FS:[0]
         *  00B6B890   50               PUSH EAX
         *  00B6B891   81EC 1C040000    SUB ESP,0x41C
         *  00B6B897   A1 E0A4F800      MOV EAX,DWORD PTR DS:[0xF8A4E0]
         *  00B6B89C   33C5             XOR EAX,EBP
         *  00B6B89E   8945 F0          MOV DWORD PTR SS:[EBP-0x10],EAX
         *  00B6B8A1   53               PUSH EBX
         *  00B6B8A2   56               PUSH ESI
         *  00B6B8A3   57               PUSH EDI
         *  00B6B8A4   50               PUSH EAX
         *  00B6B8A5   8D45 F4          LEA EAX,DWORD PTR SS:[EBP-0xC]
         *  00B6B8A8   64:A3 00000000   MOV DWORD PTR FS:[0],EAX
         *  00B6B8AE   8BD9             MOV EBX,ECX
         *  00B6B8B0   8B7D 08          MOV EDI,DWORD PTR SS:[EBP+0x8]
         *  00B6B8B3   837F 10 00       CMP DWORD PTR DS:[EDI+0x10],0x0
         *  00B6B8B7   8B45 0C          MOV EAX,DWORD PTR SS:[EBP+0xC]
         *  00B6B8BA   8985 E0FBFFFF    MOV DWORD PTR SS:[EBP-0x420],EAX
         *  00B6B8C0   8D47 10          LEA EAX,DWORD PTR DS:[EDI+0x10]
         *  00B6B8C3   89BD FCFBFFFF    MOV DWORD PTR SS:[EBP-0x404],EDI
         *  00B6B8C9   8985 F0FBFFFF    MOV DWORD PTR SS:[EBP-0x410],EAX
         *  00B6B8CF   0F84 31060000    JE .00B6BF06
         *  00B6B8D5   8B8B 1C010000    MOV ECX,DWORD PTR DS:[EBX+0x11C]
         *  00B6B8DB   B8 71F8428A      MOV EAX,0x8A42F871
         *  00B6B8E0   2B8B 18010000    SUB ECX,DWORD PTR DS:[EBX+0x118]
         *  00B6B8E6   F7E9             IMUL ECX
         *  00B6B8E8   8B85 F0FBFFFF    MOV EAX,DWORD PTR SS:[EBP-0x410]
         *  00B6B8EE   03D1             ADD EDX,ECX
         *  00B6B8F0   8B8B 20010000    MOV ECX,DWORD PTR DS:[EBX+0x120]
         *  00B6B8F6   2B8B 18010000    SUB ECX,DWORD PTR DS:[EBX+0x118]
         *  00B6B8FC   C1FA 09          SAR EDX,0x9
         *  00B6B8FF   8BF2             MOV ESI,EDX
         *  00B6B901   C1EE 1F          SHR ESI,0x1F
         *  00B6B904   03F2             ADD ESI,EDX
         *  00B6B906   0330             ADD ESI,DWORD PTR DS:[EAX]
         *  00B6B908   B8 71F8428A      MOV EAX,0x8A42F871
         *  00B6B90D   F7E9             IMUL ECX
         *  00B6B90F   03D1             ADD EDX,ECX
         *  00B6B911   C1FA 09          SAR EDX,0x9
         *  00B6B914   8BC2             MOV EAX,EDX
         *  00B6B916   C1E8 1F          SHR EAX,0x1F
         *  00B6B919   03C2             ADD EAX,EDX
         *  00B6B91B   3BC6             CMP EAX,ESI
         *  00B6B91D   73 1E            JNB SHORT .00B6B93D
         *  00B6B91F   81FE 7C214500    CMP ESI,0x45217C
         *  00B6B925   76 0A            JBE SHORT .00B6B931
         *  00B6B927   68 C031F200      PUSH .00F231C0                           ; ASCII "vector<T> too long"
         *  00B6B92C   E8 D2FC0E00      CALL .00C5B603
         *  00B6B931   56               PUSH ESI
         *  00B6B932   8D8B 18010000    LEA ECX,DWORD PTR DS:[EBX+0x118]
         *  00B6B938   E8 A38DFCFF      CALL .00B346E0
         *  00B6B93D   837F 14 08       CMP DWORD PTR DS:[EDI+0x14],0x8
         *  00B6B941   72 04            JB SHORT .00B6B947
         *  00B6B943   8B37             MOV ESI,DWORD PTR DS:[EDI]
         *  00B6B945   EB 02            JMP SHORT .00B6B949
         *  00B6B947   8BF7             MOV ESI,EDI
         *  00B6B949   89B5 F8FBFFFF    MOV DWORD PTR SS:[EBP-0x408],ESI
         *  00B6B94F   90               NOP
         *  00B6B950   8B57 14          MOV EDX,DWORD PTR DS:[EDI+0x14]
         *  00B6B953   83FA 08          CMP EDX,0x8
         *  00B6B956   72 04            JB SHORT .00B6B95C
         *  00B6B958   8B07             MOV EAX,DWORD PTR DS:[EDI]
         *  00B6B95A   EB 02            JMP SHORT .00B6B95E
         *  00B6B95C   8BC7             MOV EAX,EDI
         *  00B6B95E   8B8D F0FBFFFF    MOV ECX,DWORD PTR SS:[EBP-0x410]
         *  00B6B964   8B09             MOV ECX,DWORD PTR DS:[ECX]
         *  00B6B966   03C9             ADD ECX,ECX
         *  00B6B968   03C1             ADD EAX,ECX
         *  00B6B96A   3BF0             CMP ESI,EAX
         *  00B6B96C   0F84 94050000    JE .00B6BF06
         *  00B6B972   8B85 FCFBFFFF    MOV EAX,DWORD PTR SS:[EBP-0x404]
         *  00B6B978   8BFE             MOV EDI,ESI
         *  00B6B97A   C785 00FCFFFF 00>MOV DWORD PTR SS:[EBP-0x400],0x0
         *  00B6B984   C785 E8FBFFFF FF>MOV DWORD PTR SS:[EBP-0x418],-0x1
         *  00B6B98E   83FA 08          CMP EDX,0x8
         *  00B6B991   72 02            JB SHORT .00B6B995
         *  00B6B993   8B00             MOV EAX,DWORD PTR DS:[EAX]
         *  00B6B995   03C1             ADD EAX,ECX
         *  00B6B997   8D95 00FCFFFF    LEA EDX,DWORD PTR SS:[EBP-0x400]
         *  00B6B99D   8D8D E8FBFFFF    LEA ECX,DWORD PTR SS:[EBP-0x418]
         *  00B6B9A3   51               PUSH ECX
         *  00B6B9A4   50               PUSH EAX
         *  00B6B9A5   8D8D F8FBFFFF    LEA ECX,DWORD PTR SS:[EBP-0x408]
         *  00B6B9AB   E8 5025FBFF      CALL .00B1DF00
         *  00B6B9B0   8BB5 E8FBFFFF    MOV ESI,DWORD PTR SS:[EBP-0x418]
         *  00B6B9B6   83C4 08          ADD ESP,0x8
         *  00B6B9B9   83FE 0A          CMP ESI,0xA
         *  00B6B9BC   75 18            JNZ SHORT .00B6B9D6
         *  00B6B9BE   8BCB             MOV ECX,EBX
         *  00B6B9C0   E8 FB070000      CALL .00B6C1C0
         *  00B6B9C5   8BB5 F8FBFFFF    MOV ESI,DWORD PTR SS:[EBP-0x408]
         *  00B6B9CB   8BBD FCFBFFFF    MOV EDI,DWORD PTR SS:[EBP-0x404]
         *  00B6B9D1  ^E9 7AFFFFFF      JMP .00B6B950
         *  00B6B9D6   83FE 07          CMP ESI,0x7
         *  00B6B9D9   75 38            JNZ SHORT .00B6BA13
         *  00B6B9DB   33C0             XOR EAX,EAX
         *  00B6B9DD   C783 EC000000 00>MOV DWORD PTR DS:[EBX+0xEC],0x0
         *  00B6B9E7   8BCB             MOV ECX,EBX
         *  00B6B9E9   66:8983 F0000000 MOV WORD PTR DS:[EBX+0xF0],AX
         *  00B6B9F0   8983 F4000000    MOV DWORD PTR DS:[EBX+0xF4],EAX
         *  00B6B9F6   E8 C5070000      CALL .00B6C1C0
         *  00B6B9FB   8BB5 F8FBFFFF    MOV ESI,DWORD PTR SS:[EBP-0x408]
         *  00B6BA01   8BBD FCFBFFFF    MOV EDI,DWORD PTR SS:[EBP-0x404]
         *  00B6BA07   C683 FD000000 01 MOV BYTE PTR DS:[EBX+0xFD],0x1
         *  00B6BA0E  ^E9 3DFFFFFF      JMP .00B6B950
         *  00B6BA13   8B85 00FCFFFF    MOV EAX,DWORD PTR SS:[EBP-0x400]
         *  00B6BA19   85C0             TEST EAX,EAX
         *  00B6BA1B   75 3A            JNZ SHORT .00B6BA57
         *  00B6BA1D   85F6             TEST ESI,ESI
         *  00B6BA1F   0F84 BE000000    JE .00B6BAE3
         *  00B6BA25   85C0             TEST EAX,EAX
         *  00B6BA27   75 2E            JNZ SHORT .00B6BA57
         *  00B6BA29   A1 486A2C05      MOV EAX,DWORD PTR DS:[0x52C6A48]
         *  00B6BA2E   A8 01            TEST AL,0x1
         *  00B6BA30   75 0D            JNZ SHORT .00B6BA3F
         *  00B6BA32   83C8 01          OR EAX,0x1
         *  00B6BA35   A3 486A2C05      MOV DWORD PTR DS:[0x52C6A48],EAX
         *  00B6BA3A   E8 B15F0B00      CALL .00C219F0
         *  00B6BA3F   0FB7C6           MOVZX EAX,SI
         *  00B6BA42   80B8 506A2C05 01 CMP BYTE PTR DS:[EAX+0x52C6A50],0x1
         *  00B6BA49   75 0C            JNZ SHORT .00B6BA57
         *  00B6BA4B   8B43 6C          MOV EAX,DWORD PTR DS:[EBX+0x6C]
         *  00B6BA4E   99               CDQ
         *  00B6BA4F   2BC2             SUB EAX,EDX
         *  00B6BA51   8BC8             MOV ECX,EAX
         *  00B6BA53   D1F9             SAR ECX,1
         *  00B6BA55   EB 03            JMP SHORT .00B6BA5A
         *  00B6BA57   8B4B 6C          MOV ECX,DWORD PTR DS:[EBX+0x6C]
         *  00B6BA5A   8B15 9C5DFA00    MOV EDX,DWORD PTR DS:[0xFA5D9C]
         *  00B6BA60   898D ECFBFFFF    MOV DWORD PTR SS:[EBP-0x414],ECX
         *  00B6BA66   83BA 84CF0000 01 CMP DWORD PTR DS:[EDX+0xCF84],0x1
         *  00B6BA6D   75 26            JNZ SHORT .00B6BA95
         *  00B6BA6F   8B43 60          MOV EAX,DWORD PTR DS:[EBX+0x60]
         *  00B6BA72   03C1             ADD EAX,ECX
         *  00B6BA74   8B8B AC000000    MOV ECX,DWORD PTR DS:[EBX+0xAC]
         *  00B6BA7A   8985 04FCFFFF    MOV DWORD PTR SS:[EBP-0x3FC],EAX
         *  00B6BA80   8B43 18          MOV EAX,DWORD PTR DS:[EBX+0x18]
         *  00B6BA83   03C1             ADD EAX,ECX
         *  00B6BA85   3985 04FCFFFF    CMP DWORD PTR SS:[EBP-0x3FC],EAX
         *  00B6BA8B   7F 39            JG SHORT .00B6BAC6
         *  00B6BA8D   398D 04FCFFFF    CMP DWORD PTR SS:[EBP-0x3FC],ECX
         *  00B6BA93   EB 24            JMP SHORT .00B6BAB9
         *  00B6BA95   8B43 5C          MOV EAX,DWORD PTR DS:[EBX+0x5C]
         *  00B6BA98   03C1             ADD EAX,ECX
         *  00B6BA9A   8B8B A8000000    MOV ECX,DWORD PTR DS:[EBX+0xA8]
         *  00B6BAA0   8985 04FCFFFF    MOV DWORD PTR SS:[EBP-0x3FC],EAX
         *  00B6BAA6   8B43 18          MOV EAX,DWORD PTR DS:[EBX+0x18]
         *  00B6BAA9   03C1             ADD EAX,ECX
         *  00B6BAAB   3985 04FCFFFF    CMP DWORD PTR SS:[EBP-0x3FC],EAX
         *  00B6BAB1   7F 13            JG SHORT .00B6BAC6
         *  00B6BAB3   398D 04FCFFFF    CMP DWORD PTR SS:[EBP-0x3FC],ECX
         *  00B6BAB9   7E 3F            JLE SHORT .00B6BAFA
         *  00B6BABB   8BCE             MOV ECX,ESI
         *  00B6BABD   E8 EEF9FFFF      CALL .00B6B4B0
         *  00B6BAC2   84C0             TEST AL,AL
         *  00B6BAC4   75 34            JNZ SHORT .00B6BAFA
         *  00B6BAC6   8BCB             MOV ECX,EBX
         *  00B6BAC8   E8 F3060000      CALL .00B6C1C0
         *  00B6BACD   83BD 00FCFFFF 00 CMP DWORD PTR SS:[EBP-0x400],0x0
         *  00B6BAD4   75 1E            JNZ SHORT .00B6BAF4
         *  00B6BAD6   83FE 20          CMP ESI,0x20
         *  00B6BAD9   74 08            JE SHORT .00B6BAE3
         *  00B6BADB   81FE 00300000    CMP ESI,0x3000
         *  00B6BAE1   75 11            JNZ SHORT .00B6BAF4
         *  00B6BAE3   8BB5 F8FBFFFF    MOV ESI,DWORD PTR SS:[EBP-0x408]
         *  00B6BAE9   8BBD FCFBFFFF    MOV EDI,DWORD PTR SS:[EBP-0x404]
         *  00B6BAEF  ^E9 5CFEFFFF      JMP .00B6B950
         *  00B6BAF4   8B15 9C5DFA00    MOV EDX,DWORD PTR DS:[0xFA5D9C]
         *  00B6BAFA   83BA 84CF0000 01 CMP DWORD PTR DS:[EDX+0xCF84],0x1
         *  00B6BB01   75 66            JNZ SHORT .00B6BB69
         *  00B6BB03   8B83 A8000000    MOV EAX,DWORD PTR DS:[EBX+0xA8]
         *  00B6BB09   F7D8             NEG EAX
         *  00B6BB0B   3943 5C          CMP DWORD PTR DS:[EBX+0x5C],EAX
         *  00B6BB0E   7F 68            JG SHORT .00B6BB78
         *  00B6BB10   8B9D E0FBFFFF    MOV EBX,DWORD PTR SS:[EBP-0x420]
         *  00B6BB16   85DB             TEST EBX,EBX
         *  00B6BB18   0F84 E8030000    JE .00B6BF06
         *  00B6BB1E   8B8D FCFBFFFF    MOV ECX,DWORD PTR SS:[EBP-0x404]
         *  00B6BB24   8379 14 08       CMP DWORD PTR DS:[ECX+0x14],0x8
         *  00B6BB28   72 02            JB SHORT .00B6BB2C
         *  00B6BB2A   8B09             MOV ECX,DWORD PTR DS:[ECX]
         *  00B6BB2C   8B85 F0FBFFFF    MOV EAX,DWORD PTR SS:[EBP-0x410]
         *  00B6BB32   C745 EC 07000000 MOV DWORD PTR SS:[EBP-0x14],0x7
         *  00B6BB39   C745 E8 00000000 MOV DWORD PTR SS:[EBP-0x18],0x0
         *  00B6BB40   8B00             MOV EAX,DWORD PTR DS:[EAX]
         *  00B6BB42   8D0441           LEA EAX,DWORD PTR DS:[ECX+EAX*2]
         *  00B6BB45   33C9             XOR ECX,ECX
         *  00B6BB47   66:894D D8       MOV WORD PTR SS:[EBP-0x28],CX
         *  00B6BB4B   3BF8             CMP EDI,EAX
         *  00B6BB4D   74 0E            JE SHORT .00B6BB5D
         *  00B6BB4F   2BC7             SUB EAX,EDI
         *  00B6BB51   8D4D D8          LEA ECX,DWORD PTR SS:[EBP-0x28]
         *  00B6BB54   D1F8             SAR EAX,1
         *  00B6BB56   50               PUSH EAX
         *  00B6BB57   57               PUSH EDI
         *  00B6BB58   E8 E334F2FF      CALL .00A8F040
         *  00B6BB5D   C745 FC 00000000 MOV DWORD PTR SS:[EBP-0x4],0x0
         *  00B6BB64   E9 82030000      JMP .00B6BEEB
         *  00B6BB69   8B43 60          MOV EAX,DWORD PTR DS:[EBX+0x60]
         *  00B6BB6C   3B83 AC000000    CMP EAX,DWORD PTR DS:[EBX+0xAC]
         *  00B6BB72   0F8D 23030000    JGE .00B6BE9B
         *  00B6BB78   8D8D 08FCFFFF    LEA ECX,DWORD PTR SS:[EBP-0x3F8]
         *  00B6BB7E   E8 EDDEFFFF      CALL .00B69A70
         *  00B6BB83   C745 FC 02000000 MOV DWORD PTR SS:[EBP-0x4],0x2
         *  00B6BB8A   8B43 78          MOV EAX,DWORD PTR DS:[EBX+0x78]
         *  00B6BB8D   8B15 C05DFA00    MOV EDX,DWORD PTR DS:[0xFA5DC0]
         *  00B6BB93   8985 F4FBFFFF    MOV DWORD PTR SS:[EBP-0x40C],EAX
         *  00B6BB99   83F8 FF          CMP EAX,-0x1
         *  00B6BB9C   75 23            JNZ SHORT .00B6BBC1
         *  00B6BB9E   80BA 60010000 00 CMP BYTE PTR DS:[EDX+0x160],0x0
         *  00B6BBA5   74 11            JE SHORT .00B6BBB8
         *  00B6BBA7   8B83 E0000000    MOV EAX,DWORD PTR DS:[EBX+0xE0]
         *  00B6BBAD   8985 F4FBFFFF    MOV DWORD PTR SS:[EBP-0x40C],EAX
         *  00B6BBB3   83F8 FF          CMP EAX,-0x1
         *  00B6BBB6   75 09            JNZ SHORT .00B6BBC1
         *  00B6BBB8   8B43 24          MOV EAX,DWORD PTR DS:[EBX+0x24]
         *  00B6BBBB   8985 F4FBFFFF    MOV DWORD PTR SS:[EBP-0x40C],EAX
         *  00B6BBC1   8B4B 7C          MOV ECX,DWORD PTR DS:[EBX+0x7C]
         *  00B6BBC4   898D E4FBFFFF    MOV DWORD PTR SS:[EBP-0x41C],ECX
         *  00B6BBCA   83F9 FF          CMP ECX,-0x1
         *  00B6BBCD   75 23            JNZ SHORT .00B6BBF2
         *  00B6BBCF   80BA 60010000 00 CMP BYTE PTR DS:[EDX+0x160],0x0
         *  00B6BBD6   74 11            JE SHORT .00B6BBE9
         *  00B6BBD8   8B8B E4000000    MOV ECX,DWORD PTR DS:[EBX+0xE4]
         *  00B6BBDE   898D E4FBFFFF    MOV DWORD PTR SS:[EBP-0x41C],ECX
         *  00B6BBE4   83F9 FF          CMP ECX,-0x1
         *  00B6BBE7   75 09            JNZ SHORT .00B6BBF2
         *  00B6BBE9   8B43 28          MOV EAX,DWORD PTR DS:[EBX+0x28]
         *  00B6BBEC   8985 E4FBFFFF    MOV DWORD PTR SS:[EBP-0x41C],EAX
         *  00B6BBF2   8B83 80000000    MOV EAX,DWORD PTR DS:[EBX+0x80]
         *  00B6BBF8   8985 04FCFFFF    MOV DWORD PTR SS:[EBP-0x3FC],EAX
         *  00B6BBFE   83F8 FF          CMP EAX,-0x1
         *  00B6BC01   75 23            JNZ SHORT .00B6BC26
         *  00B6BC03   80BA 60010000 00 CMP BYTE PTR DS:[EDX+0x160],0x0
         *  00B6BC0A   74 11            JE SHORT .00B6BC1D
         *  00B6BC0C   8B83 E8000000    MOV EAX,DWORD PTR DS:[EBX+0xE8]
         *  00B6BC12   8985 04FCFFFF    MOV DWORD PTR SS:[EBP-0x3FC],EAX
         *  00B6BC18   83F8 FF          CMP EAX,-0x1
         *  00B6BC1B   75 09            JNZ SHORT .00B6BC26
         *  00B6BC1D   8B43 2C          MOV EAX,DWORD PTR DS:[EBX+0x2C]
         *  00B6BC20   8985 04FCFFFF    MOV DWORD PTR SS:[EBP-0x3FC],EAX
         *  00B6BC26   8B53 68          MOV EDX,DWORD PTR DS:[EBX+0x68]
         *  00B6BC29   0353 60          ADD EDX,DWORD PTR DS:[EBX+0x60]
         *  00B6BC2C   8B4B 5C          MOV ECX,DWORD PTR DS:[EBX+0x5C]
         *  00B6BC2F   034B 64          ADD ECX,DWORD PTR DS:[EBX+0x64]
         *  00B6BC32   83BD 00FCFFFF 01 CMP DWORD PTR SS:[EBP-0x400],0x1
         *  00B6BC39   8BB5 F4FBFFFF    MOV ESI,DWORD PTR SS:[EBP-0x40C]
         *  00B6BC3F   8B43 6C          MOV EAX,DWORD PTR DS:[EBX+0x6C]
         *  00B6BC42   C785 DCFBFFFF 00>MOV DWORD PTR SS:[EBP-0x424],0x0
         *  00B6BC4C   0F44B5 DCFBFFFF  CMOVE ESI,DWORD PTR SS:[EBP-0x424]
         *  00B6BC53   80BB FE000000 00 CMP BYTE PTR DS:[EBX+0xFE],0x0
         *  00B6BC5A   89B5 F4FBFFFF    MOV DWORD PTR SS:[EBP-0x40C],ESI
         *  00B6BC60   8BB5 00FCFFFF    MOV ESI,DWORD PTR SS:[EBP-0x400]
         *  00B6BC66   8985 10FCFFFF    MOV DWORD PTR SS:[EBP-0x3F0],EAX
         *  00B6BC6C   8B85 F4FBFFFF    MOV EAX,DWORD PTR SS:[EBP-0x40C]
         *  00B6BC72   8985 14FCFFFF    MOV DWORD PTR SS:[EBP-0x3EC],EAX
         *  00B6BC78   8B85 E4FBFFFF    MOV EAX,DWORD PTR SS:[EBP-0x41C]
         *  00B6BC7E   89B5 08FCFFFF    MOV DWORD PTR SS:[EBP-0x3F8],ESI
         *  00B6BC84   8BB5 E8FBFFFF    MOV ESI,DWORD PTR SS:[EBP-0x418]
         *  00B6BC8A   8985 18FCFFFF    MOV DWORD PTR SS:[EBP-0x3E8],EAX
         *  00B6BC90   8B85 04FCFFFF    MOV EAX,DWORD PTR SS:[EBP-0x3FC]
         *  00B6BC96   89B5 0CFCFFFF    MOV DWORD PTR SS:[EBP-0x3F4],ESI
         *  00B6BC9C   8985 1CFCFFFF    MOV DWORD PTR SS:[EBP-0x3E4],EAX
         *  00B6BCA2   898D 20FCFFFF    MOV DWORD PTR SS:[EBP-0x3E0],ECX
         *  00B6BCA8   8995 24FCFFFF    MOV DWORD PTR SS:[EBP-0x3DC],EDX
         *  00B6BCAE   74 19            JE SHORT .00B6BCC9
         *  00B6BCB0   8B43 5C          MOV EAX,DWORD PTR DS:[EBX+0x5C]
         *  00B6BCB3   8983 00010000    MOV DWORD PTR DS:[EBX+0x100],EAX
         *  00B6BCB9   8B43 60          MOV EAX,DWORD PTR DS:[EBX+0x60]
         *  00B6BCBC   8983 04010000    MOV DWORD PTR DS:[EBX+0x104],EAX
         *  00B6BCC2   C683 FE000000 00 MOV BYTE PTR DS:[EBX+0xFE],0x0
         *  00B6BCC9   A1 9C5DFA00      MOV EAX,DWORD PTR DS:[0xFA5D9C]
         *  00B6BCCE   83B8 84CF0000 01 CMP DWORD PTR DS:[EAX+0xCF84],0x1
         *  00B6BCD5   8B43 70          MOV EAX,DWORD PTR DS:[EBX+0x70]
         *  00B6BCD8   75 0B            JNZ SHORT .00B6BCE5
         *  00B6BCDA   0385 ECFBFFFF    ADD EAX,DWORD PTR SS:[EBP-0x414]
         *  00B6BCE0   0143 60          ADD DWORD PTR DS:[EBX+0x60],EAX
         *  00B6BCE3   EB 09            JMP SHORT .00B6BCEE
         *  00B6BCE5   0385 ECFBFFFF    ADD EAX,DWORD PTR SS:[EBP-0x414]
         *  00B6BCEB   0143 5C          ADD DWORD PTR DS:[EBX+0x5C],EAX
         *  00B6BCEE   8B8D 00FCFFFF    MOV ECX,DWORD PTR SS:[EBP-0x400]
         *  00B6BCF4   85C9             TEST ECX,ECX
         *  00B6BCF6   75 42            JNZ SHORT .00B6BD3A
         *  00B6BCF8   81FE 0C300000    CMP ESI,0x300C ; jichi: type2 found here
         *  00B6BCFE   74 10            JE SHORT .00B6BD10
         *  00B6BD00   81FE 0E300000    CMP ESI,0x300E
         *  00B6BD06   74 08            JE SHORT .00B6BD10
         *  00B6BD08   81FE 08FF0000    CMP ESI,0xFF08
         *  00B6BD0E   75 2A            JNZ SHORT .00B6BD3A
         *  00B6BD10   80BB FD000000 00 CMP BYTE PTR DS:[EBX+0xFD],0x0
         *  00B6BD17   74 10            JE SHORT .00B6BD29
         *  00B6BD19   56               PUSH ESI
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
            //enum { addr_offset = sizeof(bytes) - cur_ins_size }; // = 14 - 2  = 12, current inst is the last one

            ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
            ULONG addr;
            { // type 1
                const BYTE bytes[] = {
                  0x3b,0xd7,  // cmp edx,edi ; hook here
                  0x75,0x4b   // jnz short
                };
                //enum { addr_offset = 0 };
                addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
                if (addr)
                    ConsoleOutput("vnreng:Siglus2: type 1 pattern found");
            }
            if (!addr) {
                // 81fe0c300000
                const BYTE bytes[] = {
                  0x81,0xfe, 0x0c,0x30,0x00,0x00 // 0114124a   81fe 0c300000    cmp esi,0x300c  ; jichi: hook here
                };
                //enum { addr_offset = 0 };
                addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
                if (addr)
                    ConsoleOutput("vnreng:Siglus2: type 2 pattern found");
            }

            if (!addr) {
                ConsoleOutput("vnreng:Siglus2: both type1 and type2 patterns not found");
                return false;
            }

            HookParam hp = {};
            hp.address = addr;
            hp.offset = pusha_esi_off - 4; // -0x20
            hp.type = USING_UNICODE | FIXING_SPLIT; // jichi 6/1/2014: fixing the split value
            hp.length_offset = 1;

            ConsoleOutput("vnreng: INSERT Siglus2");
            NewHook(hp, "SiglusEngine2");
            //ConsoleOutput("SiglusEngine2");
            return true;
        }

        static void SpecialHookSiglus1(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            __asm
            {
                mov edx, esp_base
                mov ecx, [edx - 0xc]
                mov eax, [ecx + 0x14]
                add ecx, 4
                cmp eax, 0x8
                cmovnb ecx, [ecx]
                mov edx, len
                add eax, eax
                mov[edx], eax
                mov edx, data
                mov[edx], ecx
            }
        }

        // jichi: 8/17/2013: Change return type to bool
        bool InsertSiglus1Hook()
        {
            const BYTE bytes[] = { 0x33,0xc0,0x8b,0xf9,0x89,0x7c,0x24 };
            ULONG range = max(processStopAddress - processStartAddress, MAX_REL_ADDR);
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
            if (!addr) { // jichi 8/17/2013: Add "== 0" check to prevent breaking new games
              //ConsoleOutput("Unknown SiglusEngine");
                ConsoleOutput("vnreng:Siglus: pattern not found");
                return false;
            }

            DWORD limit = addr - 0x100;
            while (addr > limit) {
                if (*(WORD*)addr == 0xff6a) {
                    HookParam hp = {};
                    hp.address = addr;
                    hp.text_fun = SpecialHookSiglus1;
                    hp.type = USING_UNICODE;
                    ConsoleOutput("vnreng: INSERT Siglus");
                    NewHook(hp, "SiglusEngine");
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
        ok = InsertSiglus4Hook() || ok;
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
    static void SpecialHookMajiro(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
    {
        // jichi 5/12/2014
        // See: http://stackoverflow.com/questions/14210614/bind-function-parameter-to-specific-register
        // x86-64, the first 6 (integral) parameters are passed in the registers %rdi, %rsi, %rdx, %rcx, %r8, and %r9.
        __asm
        {
            mov edx, esp_base
            mov edi, [edx + 0xc]; jichi 5 / 11 / 2014: the third function parameter is LPCSTR text
            mov eax, data
            mov[eax], edi
            or ecx, 0xffffffff
            xor eax, eax
            repne scasb
            not ecx
            dec ecx
            mov eax, len
            mov[eax], ecx
            mov eax, [edx + 4]; jichi 5 / 11 / 2014: the first function parameter is LPCSTR font name(MS Gothic)
            mov edx, [eax + 0x28]; 0x28 and 0x48 are in the caller of this fuction hook
            mov eax, [eax + 0x48]; *split = ([eax + 0x28] & 0xff) | (([eax + 0x48] >> 1) & 0xffff00)
            sar eax, 0x1f
            mov dh, al
            mov ecx, split
            mov[ecx], edx
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
     *  New Majiro since [141128] [アトリエさくら] 流され妻、綾�“ネトラレ”��体験版
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
     *  Sample game: [141128] [チュアブルソフト] 残念な俺達�青春事情
     *  Following are memory values after arg4 (font name)
     *
     *  Surface: � *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  �� �ゴシヂ�.
     *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
     *  00EC5420  01 00 00 00 00 00 00 00 1C 00 00 00 0D 00 00 00   ....... .......
     *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -...���.... .... ; jichi: first byte as split in parenthesis
     *  00EC5440  00(00 00 00)60 F7 3F 00 F0 D8 FF FF 00 00 00 00  ....`・.   ....  ; jichi: first word without first byte as split
     *
     *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ......� ..・..
     *  00EC5460  00 00 00 00 01 00 00 00 00 00 00 00 32 01 00 00  .... .......2 ..
     *  00EC5470  14 00 00 00 01 00 00 00 82 6C 82 72 20 82 6F 83   ... ...�� �・ ; MS P Gothic
     *  00EC5480  53                                               S
     *
     *  Furigana: そ�
     *  00EC5400  82 6C 82 72 20 83 53 83 56 83 62 83 4E 00 4E 00  �� ゴシヂ�.N.
     *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
     *  00EC5420  01 00 00 00 00 00 00 00 0E 00 00 00 06 00 00 00   ....... ... ...
     *  00EC5430 (16)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00   ...���.... ....
     *  00EC5440  00(00 00 00)60 F7 3F 00 F0 D8 FF FF 00 00 00 00  ....`・.   ....
     *
     *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ......� ..・..
     *  00EC5460  00 00 00 00 00 00 00 00 00 00 00 00 32 01 00 00  ............2 ..
     *  00EC5470  14 00 00 00 01 00 00 00 82 6C 82 72 20 82 6F 83   ... ...�� �・ ; MS P Gothic
     *  00EC5480  53                                               S
     *
     *  Furigana: そ�
     *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  �� �ゴシヂ�.
     *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
     *  00EC5420  01 00 00 00 00 00 00 00 0E 00 00 00 06 00 00 00   ....... ... ...
     *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -...���.... ....
     *  00EC5440  00(00 00 00)60 F7 3F 00 2B 01 00 00 06 00 00 00  ....`・.+ .. ...
     *
     *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ......� ..・..
     *  00EC5460  00 00 00 00 00 00 00 00 00 00 00 00 32 01 00 00  ............2 ..
     *  00EC5470  14 00 00 00 01 00 00 00 82 6C 82 72 20 82 6F 83   ... ...�� �・ ; MS P Gothic
     *  00EC5480  53                                               S
     *
     *  ---- need to split the above and below case
     *
     *  Text: � *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  �� �ゴシヂ�.
     *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
     *  00EC5420  01 00 00 00 00 00 00 00 1C 00 00 00 0D 00 00 00   ....... .......
     *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -...���.... .... ; jichi: first byte as split in parenthesis
     *  00EC5440  FF(FF FF FF)60 F7 3F 00 32 01 00 00 14 00 00 00  ����`・.2 .. ... ; jichi: first word without first byte as split
     *
     *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ......� ..・..
     *  00EC5460  00 00 00 00 01 00 00 00 00 00 00 00 32 01 00 00  .... .......2 ..
     *  00EC5470  14 00 00 00 00 00 00 00 82 6C 82 72 20 82 6F 83   .......�� �・ ; MS P Gothic
     *  00EC5480  53                                               S
     *
     *  Text: らには、一人の少女� *  00EC5400  82 6C 82 72 20 82 6F 83 53 83 56 83 62 83 4E 00  �� �ゴシヂ�.
     *  00EC5410  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
     *  00EC5420  01 00 00 00 00 00 00 00 1C 00 00 00 0D 00 00 00   ....... .......
     *  00EC5430 (2D)00 00 00 FF FF FF 00 00 00 00 02 00 00 00 00  -...���.... ....
     *  00EC5440  FF(FF FF FF)60 F7 3F 00 4D 01 00 00 14 00 00 00  ����`・.M .. ...
     *
     *  00EC5450  32 01 00 00 0C 00 00 00 A0 02 00 00 88 00 00 00  2 ......� ..・..
     *  00EC5460  00 00 00 00 01 00 00 00 00 00 00 00 32 01 00 00  .... .......2 ..
     *  00EC5470  14 00 00 00 00 00 00 00 82 6C 82 72 20 82 6F 83   .......�� �・ ; MS P Gothic
     *  00EC5480  53                                               S
     */

    namespace { // unnamed

    // These values are the same as the assembly logic of ITH:
    //     ([eax+0x28] & 0xff) | (([eax+0x48] >> 1) & 0xffffff00)
    // 0x28 = 10 * 4, 0x48 = 18 / 4
        inline DWORD MajiroOldFontSplit(const DWORD* arg) // arg is supposed to be a string, though
        {
            return (arg[10] & 0xff) | ((arg[18] >> 1) & 0xffffff00);
        }

        // Remove lower bytes use 0xffffff00, which are different for furigana
        inline DWORD MajiroNewFontSplit(const DWORD* arg) // arg is supposed to be a string, though
        {
            return (arg[12] & 0xff) | (arg[16] & 0xffffff00);
        }

        void SpecialHookMajiro(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
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
                    *split = *(DWORD*)(esp_base + 0x5c); // = 4 * 23, caller's caller
            }
            else if (DWORD arg1 = argof(1, esp_base)) // old majiro
                *split = MajiroOldFontSplit((LPDWORD)arg1);
        }
    } // unnamed namespace
    bool InsertMajiroHook()
    {
        // jichi 4/19/2014: There must be a function in Majiro game which contains 6 TextOutA.
        // That function draws all texts.
        //
        // jichi 11/28/2014: Add new function signature
        const DWORD funcs[] = { // caller patterns
          0xec81,     // sub esp = 0x81,0xec byte old majiro
          0x83ec8b55  // mov ebp,esp, sub esp,*  new majiro
        };
        enum { FunctionCount = sizeof(funcs) / sizeof(*funcs) };
        ULONG addr = MemDbg::findMultiCallerAddress((ULONG)::TextOutA, funcs, FunctionCount, processStartAddress, processStopAddress);
        //ULONG addr = MemDbg::findCallerAddress((ULONG)::TextOutA, 0x83ec8b55, processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:Majiro: failed");
            return false;
        }

        bool newMajiro = 0x55 == *(BYTE*)addr;

        HookParam hp = {};
        //hp.offset=0xc;
        //hp.split=4;
        //hp.split_index=0x28;
        //hp.type|=USING_STRING|USING_SPLIT|SPLIT_INDIRECT;
        hp.address = addr;
        hp.text_fun = SpecialHookMajiro;
        hp.user_value = newMajiro;
        if (newMajiro) {
            hp.type = NO_CONTEXT; // do not use return address for new majiro
            ConsoleOutput("vnreng: INSERT Majiro2");
            NewHook(hp, "Majiro2");
        }
        else {
            ConsoleOutput("vnreng: INSERT Majiro");
            NewHook(hp, "Majiro");
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
    // It does not work for パ�プルソフトウェア games after しあわせ家族部 (2012)
        bool InsertCMVS1Hook()
        {
            enum { sub_esp = 0xec83 }; // caller pattern: sub esp = 0x83,0xec
            ULONG addr = MemDbg::findCallerAddress((ULONG)::GetGlyphOutlineA, sub_esp, processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("vnreng:CMVS1: failed");
                return false;
            }

            HookParam hp = {};
            hp.address = addr;
            hp.offset = 0x8;
            hp.split = -0x18;
            hp.type = BIG_ENDIAN | USING_SPLIT;
            hp.length_offset = 1;

            ConsoleOutput("vnreng: INSERT CMVS1");
            NewHook(hp, "CMVS");
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
            enum { addr_offset = 3 }; // offset from the beginning of the function
            ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
            // Artikash 11/9/2018: Not sure, but isn't findCallerAddress a better way to do this?
            if (!addr) addr = MemDbg::findCallerAddressAfterInt3((DWORD)GetGlyphOutlineA, processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("vnreng:CMVS2: pattern not found");
                return false;
            }

            //reladdr = 0x48ff0;
            //reladdr = 0x48ff3;
            HookParam hp = {};
            hp.address = addr + addr_offset;
            hp.offset = 0xc;
            hp.type = BIG_ENDIAN;
            hp.length_offset = 1;

            ConsoleOutput("vnreng: INSERT CMVS2");
            NewHook(hp, "CMVS2");
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
        void SpecialHookRUGP1(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            //CC_UNUSED(split);
            DWORD* stack = (DWORD*)esp_base;
            DWORD i, val;
            for (i = 0; i < 4; i++) {
                val = *stack++;
                if ((val >> 16) == 0)
                    break;

            }
            if (i < 4) {
                hp->offset = i << 2;
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
            DWORD low;
            if (!Util::CheckFile(L"rvmm.dll")) {
                ConsoleOutput("vnreng:rUGP: rvmm.dll does not exist");
                return false;
            }
            //WCHAR str[0x40];
            LPVOID ch = (LPVOID)0x8140;
            enum { range = 0x20000 };
            low = (DWORD)GetModuleHandleW(L"rvmm.dll");
            DWORD t = SearchPattern(low + range, processStopAddress, &ch, 4) + range;
            BYTE* s = (BYTE*)(low + t);
            //if (t) {
            if (t != range) { // jichi 10/1/2013: Changed to compare with 0x20000
                if (*(s - 2) != 0x81)
                    return false;
                if (DWORD i = SafeFindEntryAligned((DWORD)s, 0x200)) {
                    HookParam hp = {};
                    hp.address = i;
                    //hp.offset= -8;
                    hp.length_offset = 1;
                    hp.text_fun = SpecialHookRUGP1;
                    hp.type = BIG_ENDIAN;
                    ConsoleOutput("vnreng: INSERT rUGP#1");
                    NewHook(hp, "rUGP");
                    return true;
                }
            }
            else {
                t = SearchPattern(low, range, &s, 4);
                if (!t) {
                    ConsoleOutput("vnreng:rUGP: pattern not found");
                    //ConsoleOutput("Can't find characteristic instruction.");
                    return false;
                }

                s = (BYTE*)(low + t);
                for (int i = 0; i < 0x200; i++, s--)
                    if (s[0] == 0x90
                        && *(DWORD*)(s - 3) == 0x90909090) {
                        t = low + t - i + 1;
                        //swprintf(str, L"HookAddr 0x%.8x", t);
                        //ConsoleOutput(str);
                        HookParam hp = {};
                        hp.address = t;
                        hp.offset = 0x4;
                        hp.length_offset = 1;
                        hp.type = BIG_ENDIAN;
                        ConsoleOutput("vnreng:INSERT rUGP#2");
                        NewHook(hp, "rUGP");
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
         *  Sample game: マブラヴ オルタネイヂ�ヴ ト�タル・イクリプス
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
            if (!Util::CheckFile(L"vm60.dll") /*|| !SafeFillRange(L"vm60.dll", &low, &high)*/) {
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
            enum { addr_offset = 0x1001e51d - 0x1001e515 };
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
            //GROWL_DWORD(addr);
            if (!addr) {
                ConsoleOutput("vnreng:rUGP2: pattern not found");
                return false;
            }

            HookParam hp = {};
            hp.address = addr + addr_offset;
            hp.length_offset = 1;
            hp.offset = -8;
            hp.type = NO_CONTEXT | BIG_ENDIAN;
            ConsoleOutput("vnreng: INSERT rUGP2");
            NewHook(hp, "rUGP2");
            return true;
        }

    } // unnamed namespace

    bool InsertRUGPHook()
    {
        return InsertRUGP1Hook() || InsertRUGP2Hook();
    }

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
        hp.address = (DWORD)::GetTextExtentPoint32A;
        hp.offset = 0x8; // arg2 lpString
        hp.split = -0x18; // jichi 8/12/2014: = -4 - pusha_esp_off
        hp.length_offset = 3;
        hp.type = USING_STRING | USING_SPLIT;
        ConsoleOutput("vnreng: INSERT Lucifen");
        NewHook(hp, "Lucifen");
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

    static void InsertAliceHook1(DWORD addr)
    {
        if (!addr) {
            ConsoleOutput("vnreng:AliceHook1: failed");
            return;
        }
        for (DWORD i = addr, s = addr; i < s + 0x100; i++)
            if (*(BYTE*)i == 0xe8) { // Find the first relative call.
                DWORD j = i + 5 + *(DWORD*)(i + 1);
                while (true) { // Find the first register push onto stack.
                    DWORD c = ::disasm((BYTE*)s);
                    if (c == 1)
                        break;
                    s += c;
                }
                DWORD c = *(BYTE*)s;
                HookParam hp = {};
                hp.address = j;
                hp.offset = -0x8;
                hp.split = -8 - ((c & 0xf) << 2);
                hp.type = USING_STRING | USING_SPLIT;
                //if (s>j) hp.type^=USING_SPLIT;
                ConsoleOutput("vnreng: INSERT AliceHook1");
                NewHook(hp, "System40");
                //RegisterEngineType(ENGINE_SYS40);
                return;
            }
        ConsoleOutput("vnreng:AliceHook1: failed");
    }
    static void InsertAliceHook2(DWORD addr)
    {
        if (!addr) {
            ConsoleOutput("vnreng:AliceHook2: failed");
            return;
        }
        HookParam hp = {};
        hp.address = addr;
        hp.offset = -0x8;
        hp.index = 0x8;
        hp.length_offset = 1;
        hp.type = DATA_INDIRECT;
        ConsoleOutput("vnreng: INSERT AliceHook2");
        NewHook(hp, "System40");
        //RegisterEngineType(ENGINE_SYS40);
    }

    // jichi 8/23/2013 Move here from engine.cc
    // Do not work for the latest Alice games
    // jichi 5/13/2015: Looking for function entries in StoatSpriteEngine.dll
    bool InsertAliceHook()
    {
        DWORD addr;
        if (addr = (DWORD)GetProcAddress(GetModuleHandleW(L"SACT2.dll"), "SP_TextDraw")) {
            InsertAliceHook1(addr);
            return true;
        }
        if (addr = (DWORD)GetProcAddress(GetModuleHandleW(L"SACTDX.dll"), "SP_TextDraw")) {
            InsertAliceHook1(addr);
            return true;
        }
        //if (GetFunctionAddr("SP_SetTextSprite", &addr, &low, &high, 0) && addr) {
           // InsertAliceHook2(addr);
           // return true;
        //}
        if (addr = (DWORD)GetProcAddress(GetModuleHandleW(L"StoatSpriteEngine.dll"), "SP_SetTextSprite")) { // Artikash 6/27/2018 not sure if this works
            InsertAliceHook2(addr);
            return true;
        }
        //ConsoleOutput("vnreng:AliceHook: failed");
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
     *  ランス・クエス� /hsn4:-14@42e08a
     *    0042e08a  |. e8 91ed1f00    call Ranceque.0062ce20 ; hook here
     *    0042e08f  |. 83c4 0c        add esp,0xc
     *    0042e092  |. 5f             pop edi
     *    0042e093  |. 5e             pop esi
     *    0042e094  |. b0 01          mov al,0x1
     *    0042e096  |. 5b             pop ebx
     *    0042e097  \. c2 0400        retn 0x4
     *    0042e09a     cc             int3
     *
     *  5/7/2015  イブニクル version 1.0.1
     *  The hooked function is no longer get called after loading AliceRunPatch.dll.
     *  The hooked function is below.
     *  See also ATcode: http://capita.tistory.com/m/post/256
     *    005C40AE   CC               INT3
     *    005C40AF   CC               INT3
     *    005C40B0   53               PUSH EBX
     *    005C40B1   8B5C24 08        MOV EBX,DWORD PTR SS:[ESP+0x8]
     *    005C40B5   56               PUSH ESI
     *    005C40B6   57               PUSH EDI
     *    005C40B7   8B7B 10          MOV EDI,DWORD PTR DS:[EBX+0x10]
     *    005C40BA   8BF0             MOV ESI,EAX
     *    005C40BC   47               INC EDI
     *    005C40BD   3B7E 0C          CMP EDI,DWORD PTR DS:[ESI+0xC]
     *    005C40C0   76 0F            JBE SHORT .005C40D1
     *    005C40C2   E8 79F8FFFF      CALL .005C3940
     *    005C40C7   84C0             TEST AL,AL
     *    005C40C9   75 06            JNZ SHORT .005C40D1
     *    005C40CB   5F               POP EDI
     *    005C40CC   5E               POP ESI
     *    005C40CD   5B               POP EBX
     *    005C40CE   C2 0400          RETN 0x4
     *    005C40D1   837B 14 10       CMP DWORD PTR DS:[EBX+0x14],0x10
     *    005C40D5   72 02            JB SHORT .005C40D9
     *    005C40D7   8B1B             MOV EBX,DWORD PTR DS:[EBX]
     *    005C40D9   837E 0C 00       CMP DWORD PTR DS:[ESI+0xC],0x0
     *    005C40DD   75 15            JNZ SHORT .005C40F4
     *    005C40DF   57               PUSH EDI
     *    005C40E0   33C0             XOR EAX,EAX
     *    005C40E2   53               PUSH EBX
     *    005C40E3   50               PUSH EAX
     *    005C40E4   E8 B7400D00      CALL .006981A0
     *    005C40E9   83C4 0C          ADD ESP,0xC
     *    005C40EC   5F               POP EDI
     *    005C40ED   5E               POP ESI
     *    005C40EE   B0 01            MOV AL,0x1
     *    005C40F0   5B               POP EBX
     *    005C40F1   C2 0400          RETN 0x4
     *    005C40F4   8B46 08          MOV EAX,DWORD PTR DS:[ESI+0x8]
     *    005C40F7   57               PUSH EDI
     *    005C40F8   53               PUSH EBX
     *    005C40F9   50               PUSH EAX
     *    005C40FA   E8 A1400D00      CALL .006981A0 ; jichi: call here
     *    005C40FF   83C4 0C          ADD ESP,0xC
     *    005C4102   5F               POP EDI
     *    005C4103   5E               POP ESI
     *    005C4104   B0 01            MOV AL,0x1
     *    005C4106   5B               POP EBX
     *    005C4107   C2 0400          RETN 0x4
     *    005C410A   CC               INT3
     *    005C410B   CC               INT3
     *    005C410C   CC               INT3 *
     */
    static bool InsertSystem43OldHook(ULONG startAddress, ULONG stopAddress, LPCSTR hookName)
    {
        // i.e. 83c40c5f5eb0015bc20400cccc without leading 0xe8
        //const BYTE ins[] = {  //   005506a9  |. e8 f2fb1600    call rance01.006c02a0 ; hook here
        //  0x83,0xc4, 0x0c,    //   005506ae  |. 83c4 0c        add esp,0xc
        //  0x5f,               //   005506b1  |. 5f             pop edi
        //  0x5e,               //   005506b2  |. 5e             pop esi
        //  0xb0, 0x01,         //   005506b3  |. b0 01          mov al,0x1
        //  0x5b,               //   005506b5  |. 5b             pop ebx
        //  0xc2, 0x04,0x00,    //   005506b6  \. c2 0400        retn 0x4
        //  0xcc, 0xcc // patching a few int3 to make sure that this is at the end of the code block
        //};
        //enum { addr_offset = -5 }; // the function call before the ins
        //ULONG addr = processStartAddress; //- sizeof(ins);
        ////addr = 0x5506a9;
        //enum { near_call = 0xe8 }; // intra-module function call
        //do {
        //  //addr += sizeof(ins); // so that each time return diff address -- not needed
        //  ULONG range = min(processStopAddress - addr, MAX_REL_ADDR);
        //  addr = MemDbg::findBytes(ins, sizeof(ins), addr, addr + range);
        //  if (!addr) {
        //    //ITH_MSG(L"failed");
        //    ConsoleOutput("vnreng:System43: pattern not found");
        //    return false;
        //  }
        //  addr += addr_offset;
        //} while(near_call != *(BYTE *)addr); // function call
        //GROWL_DWORD(addr);

        // i.e. 83c40c5f5eb0015bc20400cccc without leading 0xe8
        const BYTE bytes[] = {
          0xe8, XX4,          //   005506a9  |. e8 f2fb1600    call rance01.006c02a0 ; hook here
          0x83,0xc4, 0x0c,    //   005506ae  |. 83c4 0c        add esp,0xc
          XX,                 //   005506b1  |. 5f             pop edi ; Artikash 2/9/2019 change these to wildcards: Evenicle 2 has the pops and moves switched order
          XX,                 //   005506b2  |. 5e             pop esi
          XX, XX,             //   005506b3  |. b0 01          mov al,0x1
          0x5b,               //   005506b5  |. 5b             pop ebx
          0xc2, 0x04,0x00,    //   005506b6  \. c2 0400        retn 0x4
          0xcc, 0xcc // patching a few int3 to make sure that this is at the end of the code block
        };
        enum { addr_offset = 0 };
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
        //GROWL_DWORD(addr);
        if (!addr) {
            ConsoleOutput("vnreng:System43: pattern not found");
            return false;
        }

        HookParam hp = {};
        hp.address = addr + addr_offset;
        hp.offset = 4;
        hp.split = -0x18;
        hp.type = NO_CONTEXT | USING_SPLIT | USING_STRING;
        ConsoleOutput("vnreng: INSERT System43");
        NewHook(hp, hookName);

        ConsoleOutput("vnreng:System43: disable GDI hooks"); // disable hooking to TextOutA, which is cached

        return true;
    }

    /** 5/13/2015 Add new hook for System43 engine that has no garbage threads and can detect character name
     *  Sample game: Evenicle
     *  See: http://capita.tistory.com/m/post/256
     *
     *  004EEA6C   CC               INT3
     *  004EEA6D   CC               INT3
     *  004EEA6E   CC               INT3
     *  004EEA6F   CC               INT3
     *  004EEA70   6A FF            PUSH -0x1
     *  004EEA72   68 E8267000      PUSH .007026E8
     *  004EEA77   64:A1 00000000   MOV EAX,DWORD PTR FS:[0]
     *  004EEA7D   50               PUSH EAX
     *  004EEA7E   83EC 20          SUB ESP,0x20
     *  004EEA81   A1 DCC47700      MOV EAX,DWORD PTR DS:[0x77C4DC]
     *  004EEA86   33C4             XOR EAX,ESP
     *  004EEA88   894424 1C        MOV DWORD PTR SS:[ESP+0x1C],EAX
     *  004EEA8C   53               PUSH EBX
     *  004EEA8D   55               PUSH EBP
     *  004EEA8E   56               PUSH ESI
     *  004EEA8F   57               PUSH EDI
     *  004EEA90   A1 DCC47700      MOV EAX,DWORD PTR DS:[0x77C4DC]
     *  004EEA95   33C4             XOR EAX,ESP
     *  004EEA97   50               PUSH EAX
     *  004EEA98   8D4424 34        LEA EAX,DWORD PTR SS:[ESP+0x34]
     *  004EEA9C   64:A3 00000000   MOV DWORD PTR FS:[0],EAX
     *  004EEAA2   8B4424 44        MOV EAX,DWORD PTR SS:[ESP+0x44]
     *  004EEAA6   8BF1             MOV ESI,ECX
     *  004EEAA8   E8 8346FBFF      CALL .004A3130
     *  004EEAAD   8BE8             MOV EBP,EAX
     *  004EEAAF   33DB             XOR EBX,EBX
     *  004EEAB1   3BEB             CMP EBP,EBX
     *  004EEAB3   75 07            JNZ SHORT .004EEABC
     *  004EEAB5   32C0             XOR AL,AL
     *  004EEAB7   E9 92000000      JMP .004EEB4E
     *  004EEABC   8B06             MOV EAX,DWORD PTR DS:[ESI]
     *  004EEABE   8B10             MOV EDX,DWORD PTR DS:[EAX]
     *  004EEAC0   8BCE             MOV ECX,ESI
     *  004EEAC2   FFD2             CALL EDX
     *  004EEAC4   8BC8             MOV ECX,EAX
     *  004EEAC6   C74424 28 0F0000>MOV DWORD PTR SS:[ESP+0x28],0xF
     *  004EEACE   895C24 24        MOV DWORD PTR SS:[ESP+0x24],EBX
     *  004EEAD2   885C24 14        MOV BYTE PTR SS:[ESP+0x14],BL
     *  004EEAD6   8D71 01          LEA ESI,DWORD PTR DS:[ECX+0x1]
     *  004EEAD9   8DA424 00000000  LEA ESP,DWORD PTR SS:[ESP]
     *  004EEAE0   8A11             MOV DL,BYTE PTR DS:[ECX]
     *  004EEAE2   41               INC ECX
     *  004EEAE3   3AD3             CMP DL,BL
     *  004EEAE5  ^75 F9            JNZ SHORT .004EEAE0
     *  004EEAE7   2BCE             SUB ECX,ESI
     *  004EEAE9   50               PUSH EAX
     *  004EEAEA   8BF9             MOV EDI,ECX
     *  004EEAEC   8D7424 18        LEA ESI,DWORD PTR SS:[ESP+0x18]
     *  004EEAF0   E8 CB27F1FF      CALL .004012C0
     *  004EEAF5   8B7C24 48        MOV EDI,DWORD PTR SS:[ESP+0x48]
     *  004EEAF9   895C24 3C        MOV DWORD PTR SS:[ESP+0x3C],EBX
     *  004EEAFD   8B75 3C          MOV ESI,DWORD PTR SS:[EBP+0x3C]
     *  004EEB00   E8 1B4A0100      CALL .00503520
     *  004EEB05   8BF8             MOV EDI,EAX
     *  004EEB07   8DB7 E4000000    LEA ESI,DWORD PTR DS:[EDI+0xE4]
     *  004EEB0D   8D4424 14        LEA EAX,DWORD PTR SS:[ESP+0x14]
     *  004EEB11   8BD6             MOV EDX,ESI
     *  004EEB13   E8 985CF1FF      CALL .004047B0
     *  004EEB18   BD 10000000      MOV EBP,0x10
     *  004EEB1D   84C0             TEST AL,AL
     *  004EEB1F   75 18            JNZ SHORT .004EEB39
     *  004EEB21   895E 10          MOV DWORD PTR DS:[ESI+0x10],EBX
     *  004EEB24   396E 14          CMP DWORD PTR DS:[ESI+0x14],EBP
     *  004EEB27   72 02            JB SHORT .004EEB2B
     *  004EEB29   8B36             MOV ESI,DWORD PTR DS:[ESI]
     *  004EEB2B   8D4424 14        LEA EAX,DWORD PTR SS:[ESP+0x14]
     *  004EEB2F   50               PUSH EAX
     *  004EEB30   8BCF             MOV ECX,EDI
     *  004EEB32   881E             MOV BYTE PTR DS:[ESI],BL
     *  004EEB34   E8 67CB0100      CALL .0050B6A0  ; jichi: ATcode modified here, text is on the top of the stack
     *  004EEB39   396C24 28        CMP DWORD PTR SS:[ESP+0x28],EBP
     *  004EEB3D   72 0D            JB SHORT .004EEB4C
     *  004EEB3F   8B4C24 14        MOV ECX,DWORD PTR SS:[ESP+0x14]
     *  004EEB43   51               PUSH ECX
     *  004EEB44   E8 42DC1900      CALL .0068C78B
     *  004EEB49   83C4 04          ADD ESP,0x4
     *  004EEB4C   B0 01            MOV AL,0x1
     *  004EEB4E   8B4C24 34        MOV ECX,DWORD PTR SS:[ESP+0x34]
     *  004EEB52   64:890D 00000000 MOV DWORD PTR FS:[0],ECX
     *  004EEB59   59               POP ECX
     *  004EEB5A   5F               POP EDI
     *  004EEB5B   5E               POP ESI
     *  004EEB5C   5D               POP EBP
     *  004EEB5D   5B               POP EBX
     *  004EEB5E   8B4C24 1C        MOV ECX,DWORD PTR SS:[ESP+0x1C]
     *  004EEB62   33CC             XOR ECX,ESP
     *  004EEB64   E8 9CD61900      CALL .0068C205
     *  004EEB69   83C4 2C          ADD ESP,0x2C
     *  004EEB6C   C3               RETN
     *  004EEB6D   CC               INT3
     *  004EEB6E   CC               INT3
     *
     *  Actual binary patch for Evenicle exe: http://capita.tistory.com/m/post/256
     *  {005E393B(EB), 004EEB34(E9 13 B6 21 00), 005C71E0(E9 48 2F 14 00), 005B6494(E9 10 3D 15 00), 0070A10F(90 90 90 90 90 E8 F7 9F EB FF E9 C7 D0 EB FF 90 90 90 90 90 E8 78 15 E0 FF E9 0C 4A DE FF 50 8B 87 B0 00 00 00 66 81 38 84 00 75 0E 83 78 EA 5B 75 08 E8 A2 00 00 00 58 EB C6 58 EB C8 50 52 BA E0 0B 7A 00 60 89 D7 8B 74 E4 28 B9 06 00 00 00 F3 A5 61 8B 44 E4 08 8B 40 10 85 C0 74 29 8B 44 E4 08 8B 40 14 83 F8 0F 75 08 89 54 E4 08 5A 58 EB 9D 8D 42 20 60 89 C7 8B 32 8B 4A 14 83 C1 09 F3 A4 61 89 02 EB E3 5A 58 EB 89 90 90 90 90 90 E8 6C 9F EB FF E9 F0 C2 EA FF 50 8B 44 E4 04 83 78 0C 01 76 31 8B 87 84 02 00 00 66 83 78 FC 46 75 24 83 78 F8 22 74 16 83 78 F8 13 75 18 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E8 06 00 00 00 58 EB B5 58 EB B7 60 8B 74 E4 28 BF E0 0B 7A 00 89 7C E4 28 B9 0C 00 00 00 F3 A5 61 C3)}
     *
     *  ATcode: FORCEFONT(5),ENCODEKOR,FONT(Malgun Gothic,-13),HOOK(0x0070A10F,TRANS([[ESP]+0x8],LEN([ESP]+0XC),PTRCHEAT),RETNPOS(COPY)),HOOK(0x0070A11E,TRANS([ESP],SMSTR(IGNORE)),RETNPOS(COPY)),HOOK(0x0070A19A,TRANS([[ESP]+0x8],LEN([ESP]+0XC),PTRCHEAT),RETNPOS(COPY))
     *  FilterCode: DenyWord{CUT(2)},FixLine{},KoFilter{},DumpText{},CustomDic{CDic},CustomScript{Write,Pass(-1),Cache}
     *
     *  The second hooked address pointed to the text address.
     *  The logic here is simplify buffer the read text, and replace the text by zero
     *  Then translate/paint them together.
     *  Several variables near the text address is used to check if the text is finished or not.
     *
     *  Function immediately before patched code:
     *  0070A09E   CC               INT3
     *  0070A09F   CC               INT3
     *  0070A0A0   6A FF            PUSH -0x1
     *  0070A0A2   68 358A7000      PUSH .00708A35
     *  0070A0A7   64:A1 00000000   MOV EAX,DWORD PTR FS:[0]
     *  0070A0AD   50               PUSH EAX
     *  0070A0AE   51               PUSH ECX
     *  0070A0AF   56               PUSH ESI
     *  0070A0B0   A1 DCC47700      MOV EAX,DWORD PTR DS:[0x77C4DC]
     *  0070A0B5   33C4             XOR EAX,ESP
     *  0070A0B7   50               PUSH EAX
     *  0070A0B8   8D4424 0C        LEA EAX,DWORD PTR SS:[ESP+0xC]
     *  0070A0BC   64:A3 00000000   MOV DWORD PTR FS:[0],EAX
     *  0070A0C2   C74424 14 000000>MOV DWORD PTR SS:[ESP+0x14],0x0
     *  0070A0CA   A1 54D17900      MOV EAX,DWORD PTR DS:[0x79D154]
     *  0070A0CF   8B08             MOV ECX,DWORD PTR DS:[EAX]
     *  0070A0D1   50               PUSH EAX
     *  0070A0D2   51               PUSH ECX
     *  0070A0D3   8D7424 10        LEA ESI,DWORD PTR SS:[ESP+0x10]
     *  0070A0D7   E8 6416F8FF      CALL .0068B740
     *  0070A0DC   A1 54D17900      MOV EAX,DWORD PTR DS:[0x79D154]
     *  0070A0E1   50               PUSH EAX
     *  0070A0E2   E8 A426F8FF      CALL .0068C78B
     *  0070A0E7   83C4 04          ADD ESP,0x4
     *  0070A0EA   8B4C24 0C        MOV ECX,DWORD PTR SS:[ESP+0xC]
     *  0070A0EE   64:890D 00000000 MOV DWORD PTR FS:[0],ECX
     *  0070A0F5   59               POP ECX
     *  0070A0F6   5E               POP ESI
     *  0070A0F7   83C4 10          ADD ESP,0x10
     *  0070A0FA   C3               RETN
     *  0070A0FB   C705 C4C17900 64>MOV DWORD PTR DS:[0x79C1C4],.0070B664
     *  0070A105   B9 C4C17900      MOV ECX,.0079C1C4
     *  0070A10A  ^E9 0722F8FF      JMP .0068C316
     *
     *  Patched code:
     *  0070A10F   90               NOP ; jichi: ATcode hooked here
     *  0070A110   90               NOP
     *  0070A111   90               NOP
     *  0070A112   90               NOP
     *  0070A113   90               NOP
     *  0070A114   E8 F79FEBFF      CALL .005C4110
     *  0070A119  ^E9 C7D0EBFF      JMP .005C71E5
     *  0070A11E   90               NOP
     *  0070A11F   90               NOP
     *  0070A120   90               NOP
     *  0070A121   90               NOP
     *  0070A122   90               NOP
     *  0070A123   E8 7815E0FF      CALL .0050B6A0                  ; jichi: call the original function for hookpoint #2
     *  0070A128  ^E9 0C4ADEFF      JMP .004EEB39                   ; jichi: come back to hookpoint#2
     *  0070A12D   50               PUSH EAX    ; jichi: this is for hookpoint #3, translate the text before send it to paint
     *  0070A12E   8B87 B0000000    MOV EAX,DWORD PTR DS:[EDI+0xB0]
     *  0070A134   66:8138 8400     CMP WORD PTR DS:[EAX],0x84
     *  0070A139   75 0E            JNZ SHORT .0070A149
     *  0070A13B   8378 EA 5B       CMP DWORD PTR DS:[EAX-0x16],0x5B
     *  0070A13F   75 08            JNZ SHORT .0070A149
     *  0070A141   E8 A2000000      CALL .0070A1E8
     *  0070A146   58               POP EAX
     *  0070A147  ^EB C6            JMP SHORT .0070A10F
     *  0070A149   58               POP EAX
     *  0070A14A  ^EB C8            JMP SHORT .0070A114
     *  0070A14C   50               PUSH EAX                        ; jichi: hookpoint#2 jmp here, text address is in [esp]
     *  0070A14D   52               PUSH EDX
     *  0070A14E   BA E00B7A00      MOV EDX,.007A0BE0               ; jichi: 007A0BE0 points to unused zeroed memory
     *  0070A153   60               PUSHAD                          ; jichi esp -= 0x20, now, esp[0x28] is text address, esp[0x24] = eax, and esp[0x20] = edx
     *  0070A154   89D7             MOV EDI,EDX                     ; set 007A0BE0 as the target buffer to save text, edx is never modified
     *  0070A156   8B74E4 28        MOV ESI,DWORD PTR SS:[ESP+0x28] ; set source text as target
     *  0070A15A   B9 06000000      MOV ECX,0x6                     ; move for 6 bytes
     *  0070A15F   F3:A5            REP MOVS DWORD PTR ES:[EDI],DWORD PTR DS:[ESI]
     *  0070A161   61               POPAD   ; finished saving text, now [esp] is old edx, esp[0x4] is old eax, esp[0x8] is old text address
     *  0070A162   8B44E4 08        MOV EAX,DWORD PTR SS:[ESP+0x8]  ; eax = original text address
     *  0070A166   8B40 10          MOV EAX,DWORD PTR DS:[EAX+0x10] ; eax = text[0x10]
     *  0070A169   85C0             TEST EAX,EAX                    ; if end of text,
     *  0070A16B   74 29            JE SHORT .0070A196              ; jump if eax is zero, comeback to hookpoint and ignore it
     *  0070A16D   8B44E4 08        MOV EAX,DWORD PTR SS:[ESP+0x8]  ; otherwise, if eax is not zero
     *  0070A171   8B40 14          MOV EAX,DWORD PTR DS:[EAX+0x14] ; eax = text[0x14]
     *  0070A174   83F8 0F          CMP EAX,0xF                     ; jichi: compare text[0x14] with 0xf
     *  0070A177   75 08            JNZ SHORT .0070A181             ; jump if not zero leaving text not modified, other continue and modify the text
     *  0070A179   8954E4 08        MOV DWORD PTR SS:[ESP+0x8],EDX  ; override esp+8 with edx, i.e. override text address by new text address and do translation
     *  0070A17D   5A               POP EDX
     *  0070A17E   58               POP EAX                         ; jichi: restore edx and eax, now esp is back to normal. [esp] is the new text address
     *  0070A17F  ^EB 9D            JMP SHORT .0070A11E             ; jichi: jump to the top of the hooked place (nop) and do translation before coming back
     *  0070A181   8D42 20          LEA EAX,DWORD PTR DS:[EDX+0x20] ; text is not modified, esp[0x8] is the text address, edx is the modified buffer, eax = buffer[0x20] address
     *  0070A184   60               PUSHAD                          ; jichi: esp[0x28] is now the text address
     *  0070A185   89C7             MOV EDI,EAX                     ; jichi: edx[0x20] is the target
     *  0070A187   8B32             MOV ESI,DWORD PTR DS:[EDX]      ; jichi: edx is the source
     *  0070A189   8B4A 14          MOV ECX,DWORD PTR DS:[EDX+0x14]
     *  0070A18C   83C1 09          ADD ECX,0x9                     ; move for [edx+0x14]+0x9 time
     *  0070A18F   F3:A4            REP MOVS BYTE PTR ES:[EDI],BYTE PTR DS:[ESI]    ; jichi: shift text by 0x14 dword ptr
     *  0070A191   61               POPAD                           ; jichi: now esp[0x8] is the text address
     *  0070A192   8902             MOV DWORD PTR DS:[EDX],EAX      ; eax is the new text address (edx+0x20), move the address to beginning of buffer ([edx]), i.e. edx is pointed to zero memory now
     *  0070A194  ^EB E3            JMP SHORT .0070A179             ; come bback to modify the text address
     *  0070A196   5A               POP EDX
     *  0070A197   58               POP EAX
     *  0070A198  ^EB 89            JMP SHORT .0070A123             ; jichi: come back to call
     *  0070A19A   90               NOP
     *  0070A19B   90               NOP
     *  0070A19C   90               NOP
     *  0070A19D   90               NOP
     *  0070A19E   90               NOP
     *  0070A19F   E8 6C9FEBFF      CALL .005C4110
     *  0070A1A4  ^E9 F0C2EAFF      JMP .005B6499
     *  0070A1A9   50               PUSH EAX                        ; jichi: from hookpoint #4
     *  0070A1AA   8B44E4 04        MOV EAX,DWORD PTR SS:[ESP+0x4]  ; jichi: move top of the old stack address to eax
     *  0070A1AE   8378 0C 01       CMP DWORD PTR DS:[EAX+0xC],0x1
     *  0070A1B2   76 31            JBE SHORT .0070A1E5             ; jichi: jump to leave if text[0xc] <= 0x1
     *  0070A1B4   8B87 84020000    MOV EAX,DWORD PTR DS:[EDI+0x284]
     *  0070A1BA   66:8378 FC 46    CMP WORD PTR DS:[EAX-0x4],0x46
     *  0070A1BF   75 24            JNZ SHORT .0070A1E5
     *  0070A1C1   8378 F8 22       CMP DWORD PTR DS:[EAX-0x8],0x22
     *  0070A1C5   74 16            JE SHORT .0070A1DD
     *  0070A1C7   8378 F8 13       CMP DWORD PTR DS:[EAX-0x8],0x13
     *  0070A1CB   75 18            JNZ SHORT .0070A1E5
     *  0070A1CD   90               NOP
     *  0070A1CE   90               NOP
     *  0070A1CF   90               NOP
     *  0070A1D0   90               NOP
     *  0070A1D1   90               NOP
     *  0070A1D2   90               NOP
     *  0070A1D3   90               NOP
     *  0070A1D4   90               NOP
     *  0070A1D5   90               NOP
     *  0070A1D6   90               NOP
     *  0070A1D7   90               NOP
     *  0070A1D8   90               NOP
     *  0070A1D9   90               NOP
     *  0070A1DA   90               NOP
     *  0070A1DB   90               NOP
     *  0070A1DC   90               NOP
     *  0070A1DD   E8 06000000      CALL .0070A1E8
     *  0070A1E2   58               POP EAX
     *  0070A1E3  ^EB B5            JMP SHORT .0070A19A
     *  0070A1E5   58               POP EAX
     *  0070A1E6  ^EB B7            JMP SHORT .0070A19F
     *  0070A1E8   60               PUSHAD
     *  0070A1E9   8B74E4 28        MOV ESI,DWORD PTR SS:[ESP+0x28]
     *  0070A1ED   BF E00B7A00      MOV EDI,.007A0BE0
     *  0070A1F2   897CE4 28        MOV DWORD PTR SS:[ESP+0x28],EDI
     *  0070A1F6   B9 0C000000      MOV ECX,0xC
     *  0070A1FB   F3:A5            REP MOVS DWORD PTR ES:[EDI],DWORD PTR DS:[ESI]
     *  0070A1FD   61               POPAD
     *  0070A1FE   C3               RETN
     *  0070A1FF   0000             ADD BYTE PTR DS:[EAX],AL
     *  0070A201   0000             ADD BYTE PTR DS:[EAX],AL
     *  0070A203   0000             ADD BYTE PTR DS:[EAX],AL
     *
     *  Modified places:
     *
     *  005E391C   CC               INT3
     *  005E391D   CC               INT3
     *  005E391E   CC               INT3
     *  005E391F   CC               INT3
     *  005E3920   55               PUSH EBP
     *  005E3921   8BEC             MOV EBP,ESP
     *  005E3923   83E4 C0          AND ESP,0xFFFFFFC0
     *  005E3926   83EC 34          SUB ESP,0x34
     *  005E3929   53               PUSH EBX
     *  005E392A   8B5D 08          MOV EBX,DWORD PTR SS:[EBP+0x8]
     *  005E392D   817B 04 00010000 CMP DWORD PTR DS:[EBX+0x4],0x100
     *  005E3934   56               PUSH ESI
     *  005E3935   57               PUSH EDI
     *  005E3936   8B7D 0C          MOV EDI,DWORD PTR SS:[EBP+0xC]
     *  005E3939   8BF0             MOV ESI,EAX
     *  005E393B   EB 67            JMP SHORT .005E39A4 ; jichi: here modified point#1, change to always jump to 5e39a4, when enabled it will change font size
     *  005E393D   8D4424 28        LEA EAX,DWORD PTR SS:[ESP+0x28]
     *  005E3941   50               PUSH EAX
     *  005E3942   8D4C24 30        LEA ECX,DWORD PTR SS:[ESP+0x30]
     *
     *  004EEA6E   CC               INT3
     *  004EEA6F   CC               INT3
     *  004EEA70   6A FF            PUSH -0x1
     *  004EEA72   68 E8267000      PUSH .007026E8
     *  004EEA77   64:A1 00000000   MOV EAX,DWORD PTR FS:[0]
     *  004EEA7D   50               PUSH EAX
     *  004EEA7E   83EC 20          SUB ESP,0x20
     *  004EEA81   A1 DCC47700      MOV EAX,DWORD PTR DS:[0x77C4DC]
     *  004EEA86   33C4             XOR EAX,ESP
     *  004EEA88   894424 1C        MOV DWORD PTR SS:[ESP+0x1C],EAX
     *  004EEA8C   53               PUSH EBX
     *  004EEA8D   55               PUSH EBP
     *  004EEA8E   56               PUSH ESI
     *  004EEA8F   57               PUSH EDI
     *  004EEA90   A1 DCC47700      MOV EAX,DWORD PTR DS:[0x77C4DC]
     *  004EEA95   33C4             XOR EAX,ESP
     *  004EEA97   50               PUSH EAX
     *  004EEA98   8D4424 34        LEA EAX,DWORD PTR SS:[ESP+0x34]
     *  004EEA9C   64:A3 00000000   MOV DWORD PTR FS:[0],EAX
     *  004EEAA2   8B4424 44        MOV EAX,DWORD PTR SS:[ESP+0x44]
     *  004EEAA6   8BF1             MOV ESI,ECX
     *  004EEAA8   E8 8346FBFF      CALL .004A3130
     *  004EEAAD   8BE8             MOV EBP,EAX
     *  004EEAAF   33DB             XOR EBX,EBX
     *  004EEAB1   3BEB             CMP EBP,EBX
     *  004EEAB3   75 07            JNZ SHORT .004EEABC
     *  004EEAB5   32C0             XOR AL,AL
     *  004EEAB7   E9 92000000      JMP .004EEB4E
     *  004EEABC   8B06             MOV EAX,DWORD PTR DS:[ESI]
     *  004EEABE   8B10             MOV EDX,DWORD PTR DS:[EAX]
     *  004EEAC0   8BCE             MOV ECX,ESI
     *  004EEAC2   FFD2             CALL EDX
     *  004EEAC4   8BC8             MOV ECX,EAX
     *  004EEAC6   C74424 28 0F0000>MOV DWORD PTR SS:[ESP+0x28],0xF
     *  004EEACE   895C24 24        MOV DWORD PTR SS:[ESP+0x24],EBX
     *  004EEAD2   885C24 14        MOV BYTE PTR SS:[ESP+0x14],BL
     *  004EEAD6   8D71 01          LEA ESI,DWORD PTR DS:[ECX+0x1]
     *  004EEAD9   8DA424 00000000  LEA ESP,DWORD PTR SS:[ESP]
     *  004EEAE0   8A11             MOV DL,BYTE PTR DS:[ECX]
     *  004EEAE2   41               INC ECX
     *  004EEAE3   3AD3             CMP DL,BL
     *  004EEAE5  ^75 F9            JNZ SHORT .004EEAE0
     *  004EEAE7   2BCE             SUB ECX,ESI
     *  004EEAE9   50               PUSH EAX
     *  004EEAEA   8BF9             MOV EDI,ECX
     *  004EEAEC   8D7424 18        LEA ESI,DWORD PTR SS:[ESP+0x18]
     *  004EEAF0   E8 CB27F1FF      CALL .004012C0
     *  004EEAF5   8B7C24 48        MOV EDI,DWORD PTR SS:[ESP+0x48]
     *  004EEAF9   895C24 3C        MOV DWORD PTR SS:[ESP+0x3C],EBX
     *  004EEAFD   8B75 3C          MOV ESI,DWORD PTR SS:[EBP+0x3C]
     *  004EEB00   E8 1B4A0100      CALL .00503520
     *  004EEB05   8BF8             MOV EDI,EAX
     *  004EEB07   8DB7 E4000000    LEA ESI,DWORD PTR DS:[EDI+0xE4]
     *  004EEB0D   8D4424 14        LEA EAX,DWORD PTR SS:[ESP+0x14]
     *  004EEB11   8BD6             MOV EDX,ESI
     *  004EEB13   E8 985CF1FF      CALL .004047B0
     *  004EEB18   BD 10000000      MOV EBP,0x10
     *  004EEB1D   84C0             TEST AL,AL
     *  004EEB1F   75 18            JNZ SHORT .004EEB39
     *  004EEB21   895E 10          MOV DWORD PTR DS:[ESI+0x10],EBX
     *  004EEB24   396E 14          CMP DWORD PTR DS:[ESI+0x14],EBP
     *  004EEB27   72 02            JB SHORT .004EEB2B
     *  004EEB29   8B36             MOV ESI,DWORD PTR DS:[ESI]
     *  004EEB2B   8D4424 14        LEA EAX,DWORD PTR SS:[ESP+0x14]
     *  004EEB2F   50               PUSH EAX
     *  004EEB30   8BCF             MOV ECX,EDI
     *  004EEB32   881E             MOV BYTE PTR DS:[ESI],BL
     *  004EEB34   E9 13B62100      JMP .0070A14C   ; jichi: here hookpoint#2, name is modified here, scenario and names are here accessed char by char on the top of the stack
     *  004EEB39   396C24 28        CMP DWORD PTR SS:[ESP+0x28],EBP
     *  004EEB3D   72 0D            JB SHORT .004EEB4C
     *  004EEB3F   8B4C24 14        MOV ECX,DWORD PTR SS:[ESP+0x14]
     *  004EEB43   51               PUSH ECX
     *  004EEB44   E8 42DC1900      CALL .0068C78B
     *  004EEB49   83C4 04          ADD ESP,0x4
     *  004EEB4C   B0 01            MOV AL,0x1
     *  004EEB4E   8B4C24 34        MOV ECX,DWORD PTR SS:[ESP+0x34]
     *  004EEB52   64:890D 00000000 MOV DWORD PTR FS:[0],ECX
     *  004EEB59   59               POP ECX
     *  004EEB5A   5F               POP EDI
     *  004EEB5B   5E               POP ESI
     *  004EEB5C   5D               POP EBP
     *  004EEB5D   5B               POP EBX
     *  004EEB5E   8B4C24 1C        MOV ECX,DWORD PTR SS:[ESP+0x1C]
     *  004EEB62   33CC             XOR ECX,ESP
     *  004EEB64   E8 9CD61900      CALL .0068C205
     *  004EEB69   83C4 2C          ADD ESP,0x2C
     *  004EEB6C   C3               RETN
     *  004EEB6D   CC               INT3
     *  004EEB6E   CC               INT3
     *
     *  005C70EE   CC               INT3
     *  005C70EF   CC               INT3
     *  005C70F0   83EC 18          SUB ESP,0x18
     *  005C70F3   A1 DCC47700      MOV EAX,DWORD PTR DS:[0x77C4DC]
     *  005C70F8   33C4             XOR EAX,ESP
     *  005C70FA   894424 14        MOV DWORD PTR SS:[ESP+0x14],EAX
     *  005C70FE   53               PUSH EBX
     *  005C70FF   8B5C24 20        MOV EBX,DWORD PTR SS:[ESP+0x20]
     *  005C7103   55               PUSH EBP
     *  005C7104   8B6C24 2C        MOV EBP,DWORD PTR SS:[ESP+0x2C]
     *  005C7108   8B45 1C          MOV EAX,DWORD PTR SS:[EBP+0x1C]
     *  005C710B   56               PUSH ESI
     *  005C710C   8BF2             MOV ESI,EDX
     *  005C710E   57               PUSH EDI
     *  005C710F   8BF9             MOV EDI,ECX
     *  005C7111   897424 10        MOV DWORD PTR SS:[ESP+0x10],ESI
     *  005C7115   83F8 44          CMP EAX,0x44
     *  005C7118   77 7A            JA SHORT .005C7194
     *  005C711A   0FB680 7C735C00  MOVZX EAX,BYTE PTR DS:[EAX+0x5C737C]
     *  005C7121   FF2485 60735C00  JMP DWORD PTR DS:[EAX*4+0x5C7360]
     *  005C7128   8B4B 0C          MOV ECX,DWORD PTR DS:[EBX+0xC]
     *  005C712B   8B4424 30        MOV EAX,DWORD PTR SS:[ESP+0x30]
     *  005C712F   C1E9 02          SHR ECX,0x2
     *  005C7132   3BC1             CMP EAX,ECX
     *  005C7134   73 5E            JNB SHORT .005C7194
     *  005C7136   837B 0C 00       CMP DWORD PTR DS:[EBX+0xC],0x0
     *  005C713A   75 1C            JNZ SHORT .005C7158
     *  005C713C   33DB             XOR EBX,EBX
     *  005C713E   5F               POP EDI
     *  005C713F   893483           MOV DWORD PTR DS:[EBX+EAX*4],ESI
     *  005C7142   5E               POP ESI
     *  005C7143   5D               POP EBP
     *  005C7144   B0 01            MOV AL,0x1
     *  005C7146   5B               POP EBX
     *  005C7147   8B4C24 14        MOV ECX,DWORD PTR SS:[ESP+0x14]
     *  005C714B   33CC             XOR ECX,ESP
     *  005C714D   E8 B3500C00      CALL .0068C205
     *  005C7152   83C4 18          ADD ESP,0x18
     *  005C7155   C2 0C00          RETN 0xC
     *  005C7158   8B5B 08          MOV EBX,DWORD PTR DS:[EBX+0x8]
     *  005C715B   5F               POP EDI
     *  005C715C   893483           MOV DWORD PTR DS:[EBX+EAX*4],ESI
     *  005C715F   5E               POP ESI
     *  005C7160   5D               POP EBP
     *  005C7161   B0 01            MOV AL,0x1
     *  005C7163   5B               POP EBX
     *  005C7164   8B4C24 14        MOV ECX,DWORD PTR SS:[ESP+0x14]
     *  005C7168   33CC             XOR ECX,ESP
     *  005C716A   E8 96500C00      CALL .0068C205
     *  005C716F   83C4 18          ADD ESP,0x18
     *  005C7172   C2 0C00          RETN 0xC
     *  005C7175   F3:0F104424 10   MOVSS XMM0,DWORD PTR SS:[ESP+0x10]
     *  005C717B   51               PUSH ECX
     *  005C717C   8B4C24 34        MOV ECX,DWORD PTR SS:[ESP+0x34]
     *  005C7180   8BC3             MOV EAX,EBX
     *  005C7182   F3:0F110424      MOVSS DWORD PTR SS:[ESP],XMM0
     *  005C7187   E8 14C7FFFF      CALL .005C38A0
     *  005C718C   84C0             TEST AL,AL
     *  005C718E   0F85 B2010000    JNZ .005C7346
     *  005C7194   5F               POP EDI
     *  005C7195   5E               POP ESI
     *  005C7196   5D               POP EBP
     *  005C7197   32C0             XOR AL,AL
     *  005C7199   5B               POP EBX
     *  005C719A   8B4C24 14        MOV ECX,DWORD PTR SS:[ESP+0x14]
     *  005C719E   33CC             XOR ECX,ESP
     *  005C71A0   E8 60500C00      CALL .0068C205
     *  005C71A5   83C4 18          ADD ESP,0x18
     *  005C71A8   C2 0C00          RETN 0xC
     *  005C71AB   8B4C24 30        MOV ECX,DWORD PTR SS:[ESP+0x30]
     *  005C71AF   8D5424 10        LEA EDX,DWORD PTR SS:[ESP+0x10]
     *  005C71B3   52               PUSH EDX
     *  005C71B4   8BC3             MOV EAX,EBX
     *  005C71B6   E8 25C7FFFF      CALL .005C38E0
     *  005C71BB   84C0             TEST AL,AL
     *  005C71BD  ^74 D5            JE SHORT .005C7194
     *  005C71BF   8B4C24 10        MOV ECX,DWORD PTR SS:[ESP+0x10]
     *  005C71C3   8BC7             MOV EAX,EDI
     *  005C71C5   E8 D6F0FFFF      CALL .005C62A0
     *  005C71CA   8BD8             MOV EBX,EAX
     *  005C71CC   8BCE             MOV ECX,ESI
     *  005C71CE   8BC7             MOV EAX,EDI
     *  005C71D0   E8 CBF0FFFF      CALL .005C62A0
     *  005C71D5   85DB             TEST EBX,EBX
     *  005C71D7  ^74 BB            JE SHORT .005C7194
     *  005C71D9   85C0             TEST EAX,EAX
     *  005C71DB  ^74 B7            JE SHORT .005C7194
     *  005C71DD   50               PUSH EAX
     *  005C71DE   8BC3             MOV EAX,EBX
     *  005C71E0   E8 2BCFFFFF      CALL .005C4110  ; original function call
     *  //005C71E0   E9 482F1400      JMP .0070A12D   ; jichi: here hookpoint#3, text is modified here, text in [[esp]+0x8]], length in [esp]+0xc
     *  005C71E5  ^EB A5            JMP SHORT .005C718C
     *  005C71E7   8B47 08          MOV EAX,DWORD PTR DS:[EDI+0x8]
     *  005C71EA   8B4F 0C          MOV ECX,DWORD PTR DS:[EDI+0xC]
     *  005C71ED   2BC8             SUB ECX,EAX
     *  005C71EF   C1F9 02          SAR ECX,0x2
     *  005C71F2   3BF1             CMP ESI,ECX
     *  005C71F4  ^73 9E            JNB SHORT .005C7194
     *  005C71F6   8B34B0           MOV ESI,DWORD PTR DS:[EAX+ESI*4]
     *  005C71F9   85F6             TEST ESI,ESI
     *  005C71FB  ^74 97            JE SHORT .005C7194
     *
     *  005B640E   CC               INT3
     *  005B640F   CC               INT3
     *  005B6410   53               PUSH EBX
     *  005B6411   56               PUSH ESI
     *  005B6412   B9 FCFFFFFF      MOV ECX,-0x4
     *  005B6417   57               PUSH EDI
     *  005B6418   8BF8             MOV EDI,EAX
     *  005B641A   018F B0020000    ADD DWORD PTR DS:[EDI+0x2B0],ECX
     *  005B6420   8B87 B0020000    MOV EAX,DWORD PTR DS:[EDI+0x2B0]
     *  005B6426   8B30             MOV ESI,DWORD PTR DS:[EAX]
     *  005B6428   018F B0020000    ADD DWORD PTR DS:[EDI+0x2B0],ECX
     *  005B642E   8B87 B0020000    MOV EAX,DWORD PTR DS:[EDI+0x2B0]
     *  005B6434   8B08             MOV ECX,DWORD PTR DS:[EAX]
     *  005B6436   8B87 E0010000    MOV EAX,DWORD PTR DS:[EDI+0x1E0]
     *  005B643C   2B87 DC010000    SUB EAX,DWORD PTR DS:[EDI+0x1DC]
     *  005B6442   C1F8 02          SAR EAX,0x2
     *  005B6445   3BF0             CMP ESI,EAX
     *  005B6447   73 0D            JNB SHORT .005B6456
     *  005B6449   8B87 DC010000    MOV EAX,DWORD PTR DS:[EDI+0x1DC]
     *  005B644F   8B14B0           MOV EDX,DWORD PTR DS:[EAX+ESI*4]
     *  005B6452   85D2             TEST EDX,EDX
     *  005B6454   75 13            JNZ SHORT .005B6469
     *  005B6456   68 70757200      PUSH .00727570
     *  005B645B   8BCF             MOV ECX,EDI
     *  005B645D   E8 AEC9FFFF      CALL .005B2E10
     *  005B6462   83C4 04          ADD ESP,0x4
     *  005B6465   5F               POP EDI
     *  005B6466   5E               POP ESI
     *  005B6467   5B               POP EBX
     *  005B6468   C3               RETN
     *  005B6469   8B9F E0010000    MOV EBX,DWORD PTR DS:[EDI+0x1E0]
     *  005B646F   2BD8             SUB EBX,EAX
     *  005B6471   C1FB 02          SAR EBX,0x2
     *  005B6474   3BCB             CMP ECX,EBX
     *  005B6476   73 07            JNB SHORT .005B647F
     *  005B6478   8B0488           MOV EAX,DWORD PTR DS:[EAX+ECX*4]
     *  005B647B   85C0             TEST EAX,EAX
     *  005B647D   75 14            JNZ SHORT .005B6493
     *  005B647F   51               PUSH ECX
     *  005B6480   68 A0757200      PUSH .007275A0
     *  005B6485   8BCF             MOV ECX,EDI
     *  005B6487   E8 84C9FFFF      CALL .005B2E10
     *  005B648C   83C4 08          ADD ESP,0x8
     *  005B648F   5F               POP EDI
     *  005B6490   5E               POP ESI
     *  005B6491   5B               POP EBX
     *  005B6492   C3               RETN
     *  005B6493   52               PUSH EDX
     *  005B6494   E8 77DC0000      CALL .005C4110
     *  //005B6494   E9 103D1500      JMP .0070A1A9   ; jichi: here hookpoint#4
     *  005B6499   84C0             TEST AL,AL
     *  005B649B   75 16            JNZ SHORT .005B64B3
     *  005B649D   68 D4757200      PUSH .007275D4
     *  005B64A2   B9 F0757200      MOV ECX,.007275F0                        ; ASCII "S_ASSIGN"
     *  005B64A7   E8 84C8FFFF      CALL .005B2D30
     *  005B64AC   83C4 04          ADD ESP,0x4
     *  005B64AF   5F               POP EDI
     *  005B64B0   5E               POP ESI
     *  005B64B1   5B               POP EBX
     *  005B64B2   C3               RETN
     *  005B64B3   8B8F B0020000    MOV ECX,DWORD PTR DS:[EDI+0x2B0]
     *  005B64B9   8931             MOV DWORD PTR DS:[ECX],ESI
     *  005B64BB   8387 B0020000 04 ADD DWORD PTR DS:[EDI+0x2B0],0x4
     *  005B64C2   5F               POP EDI
     *  005B64C3   5E               POP ESI
     *  005B64C4   5B               POP EBX
     *  005B64C5   C3               RETN
     *  005B64C6   CC               INT3
     *  005B64C7   CC               INT3
     *  005B64C8   CC               INT3
     *
     *  Slightly modified #4 in AliceRunPatch.dll
     *  101B6C10   5B               POP EBX
     *  101B6C11   59               POP ECX
     *  101B6C12   C3               RETN
     *  101B6C13   52               PUSH EDX
     *  101B6C14   8BC1             MOV EAX,ECX
     *  101B6C16   E9 4E7D1600      JMP .1031E969   ; jichi: hook here
     *  101B6C1B   84C0             TEST AL,AL
     *  101B6C1D   75 18            JNZ SHORT .101B6C37
     *  101B6C1F   68 FCB53310      PUSH .1033B5FC
     *  101B6C24   B9 18B63310      MOV ECX,.1033B618                        ; ASCII "S_ASSIGN"
     *  101B6C29   E8 92B8FFFF      CALL .101B24C0
     *  101B6C2E   83C4 04          ADD ESP,0x4
     *  101B6C31   5F               POP EDI
     *  101B6C32   5E               POP ESI
     *  101B6C33   5D               POP EBP
     *  101B6C34   5B               POP EBX
     *  101B6C35   59               POP ECX
     *  101B6C36   C3               RETN
     *  101B6C37   53               PUSH EBX
     *  101B6C38   56               PUSH ESI
     *  101B6C39   E8 E29C0100      CALL .101D0920
     *  101B6C3E   5F               POP EDI
     *  101B6C3F   5E               POP ESI
     *  101B6C40   5D               POP EBP
     *  101B6C41   5B               POP EBX
     *  101B6C42   59               POP ECX
     *  101B6C43   C3               RETN
     *  101B6C44   CC               INT3
     *  101B6C45   CC               INT3
     *  101B6C46   CC               INT3
     *
     *  The function get called to paint string of names for hookpoint #2, text in arg1:
     *  0050B69E   CC               INT3
     *  0050B69F   CC               INT3
     *  0050B6A0   55               PUSH EBP
     *  0050B6A1   8BEC             MOV EBP,ESP
     *  0050B6A3   83E4 F8          AND ESP,0xFFFFFFF8
     *  0050B6A6   6A FF            PUSH -0x1
     *  0050B6A8   68 F8277000      PUSH .007027F8
     *  0050B6AD   64:A1 00000000   MOV EAX,DWORD PTR FS:[0]
     *  0050B6B3   50               PUSH EAX
     *  0050B6B4   83EC 18          SUB ESP,0x18
     *  0050B6B7   53               PUSH EBX
     *  0050B6B8   56               PUSH ESI
     *  0050B6B9   57               PUSH EDI
     *  0050B6BA   A1 DCC47700      MOV EAX,DWORD PTR DS:[0x77C4DC]
     *  0050B6BF   33C4             XOR EAX,ESP
     *  0050B6C1   50               PUSH EAX
     *  0050B6C2   8D4424 28        LEA EAX,DWORD PTR SS:[ESP+0x28]
     *  0050B6C6   64:A3 00000000   MOV DWORD PTR FS:[0],EAX
     *  0050B6CC   8BF9             MOV EDI,ECX
     *  0050B6CE   57               PUSH EDI
     *  0050B6CF   E8 5CEAFFFF      CALL .0050A130
     *  0050B6D4   8B45 08          MOV EAX,DWORD PTR SS:[EBP+0x8]
     *  0050B6D7   6A FF            PUSH -0x1
     *  0050B6D9   33DB             XOR EBX,EBX
     *  0050B6DB   53               PUSH EBX
     *  0050B6DC   8DB7 E4000000    LEA ESI,DWORD PTR DS:[EDI+0xE4]
     *  0050B6E2   50               PUSH EAX
     *  0050B6E3   E8 886BEFFF      CALL .00402270
     *  0050B6E8   895C24 14        MOV DWORD PTR SS:[ESP+0x14],EBX
     *  0050B6EC   895C24 18        MOV DWORD PTR SS:[ESP+0x18],EBX
     *  0050B6F0   895C24 1C        MOV DWORD PTR SS:[ESP+0x1C],EBX
     *  0050B6F4   56               PUSH ESI
     *  0050B6F5   8D4C24 18        LEA ECX,DWORD PTR SS:[ESP+0x18]
     *  0050B6F9   51               PUSH ECX
     *  0050B6FA   57               PUSH EDI
     *  0050B6FB   895C24 3C        MOV DWORD PTR SS:[ESP+0x3C],EBX
     *  0050B6FF   E8 6C290000      CALL .0050E070
     *  0050B704   8D5424 14        LEA EDX,DWORD PTR SS:[ESP+0x14]
     *  0050B708   8BCF             MOV ECX,EDI
     *  0050B70A   E8 B1010000      CALL .0050B8C0
     *  0050B70F   8B7424 14        MOV ESI,DWORD PTR SS:[ESP+0x14]
     *  0050B713   C687 E0000000 01 MOV BYTE PTR DS:[EDI+0xE0],0x1
     *  0050B71A   3BF3             CMP ESI,EBX
     *  0050B71C   74 14            JE SHORT .0050B732
     *  0050B71E   8B7C24 18        MOV EDI,DWORD PTR SS:[ESP+0x18]
     *  0050B722   8BC6             MOV EAX,ESI
     *  0050B724   E8 7751F0FF      CALL .004108A0
     *  0050B729   56               PUSH ESI
     *  0050B72A   E8 5C101800      CALL .0068C78B
     *  0050B72F   83C4 04          ADD ESP,0x4
     *  0050B732   8B4C24 28        MOV ECX,DWORD PTR SS:[ESP+0x28]
     *  0050B736   64:890D 00000000 MOV DWORD PTR FS:[0],ECX
     *  0050B73D   59               POP ECX
     *  0050B73E   5F               POP EDI
     *  0050B73F   5E               POP ESI
     *  0050B740   5B               POP EBX
     *  0050B741   8BE5             MOV ESP,EBP
     *  0050B743   5D               POP EBP
     *  0050B744   C2 0400          RETN 0x4
     *  0050B747   CC               INT3
     *  0050B748   CC               INT3
     *  0050B749   CC               INT3
     *  0050B74A   CC               INT3
     *  0050B74B   CC               INT3
     *  0050B74C   CC               INT3
     *
     *  Function get called for hookpoint #3, text in [arg1+0x10], length in arg1+0xc, only for scenario, function call is looped
     *  005C410D   CC               INT3
     *  005C410E   CC               INT3
     *  005C410F   CC               INT3
     *  005C4110   53               PUSH EBX
     *  005C4111   8B5C24 08        MOV EBX,DWORD PTR SS:[ESP+0x8]
     *  005C4115   837B 0C 00       CMP DWORD PTR DS:[EBX+0xC],0x0
     *  005C4119   56               PUSH ESI
     *  005C411A   57               PUSH EDI
     *  005C411B   8BF0             MOV ESI,EAX
     *  005C411D   74 07            JE SHORT .005C4126
     *  005C411F   8B43 08          MOV EAX,DWORD PTR DS:[EBX+0x8]
     *  005C4122   85C0             TEST EAX,EAX
     *  005C4124   75 04            JNZ SHORT .005C412A
     *  005C4126   33C0             XOR EAX,EAX
     *  005C4128   EB 0F            JMP SHORT .005C4139
     *  005C412A   8D50 01          LEA EDX,DWORD PTR DS:[EAX+0x1]
     *  005C412D   8D49 00          LEA ECX,DWORD PTR DS:[ECX]
     *  005C4130   8A08             MOV CL,BYTE PTR DS:[EAX]
     *  005C4132   40               INC EAX
     *  005C4133   84C9             TEST CL,CL
     *  005C4135  ^75 F9            JNZ SHORT .005C4130
     *  005C4137   2BC2             SUB EAX,EDX
     *  005C4139   8D78 01          LEA EDI,DWORD PTR DS:[EAX+0x1]
     *  005C413C   3B7E 0C          CMP EDI,DWORD PTR DS:[ESI+0xC]
     *  005C413F   76 0F            JBE SHORT .005C4150
     *  005C4141   E8 FAF7FFFF      CALL .005C3940
     *  005C4146   84C0             TEST AL,AL
     *  005C4148   75 06            JNZ SHORT .005C4150
     *  005C414A   5F               POP EDI
     *  005C414B   5E               POP ESI
     *  005C414C   5B               POP EBX
     *  005C414D   C2 0400          RETN 0x4
     *  005C4150   837B 0C 00       CMP DWORD PTR DS:[EBX+0xC],0x0
     *  005C4154   75 04            JNZ SHORT .005C415A
     *  005C4156   33C9             XOR ECX,ECX
     *  005C4158   EB 03            JMP SHORT .005C415D
     *  005C415A   8B4B 08          MOV ECX,DWORD PTR DS:[EBX+0x8]
     *  005C415D   837E 0C 00       CMP DWORD PTR DS:[ESI+0xC],0x0
     *  005C4161   75 15            JNZ SHORT .005C4178
     *  005C4163   57               PUSH EDI
     *  005C4164   33C0             XOR EAX,EAX
     *  005C4166   51               PUSH ECX
     *  005C4167   50               PUSH EAX
     *  005C4168   E8 33400D00      CALL .006981A0
     *  005C416D   83C4 0C          ADD ESP,0xC
     *  005C4170   5F               POP EDI
     *  005C4171   5E               POP ESI
     *  005C4172   B0 01            MOV AL,0x1
     *  005C4174   5B               POP EBX
     *  005C4175   C2 0400          RETN 0x4
     *  005C4178   8B46 08          MOV EAX,DWORD PTR DS:[ESI+0x8]
     *  005C417B   57               PUSH EDI
     *  005C417C   51               PUSH ECX
     *  005C417D   50               PUSH EAX
     *  005C417E   E8 1D400D00      CALL .006981A0
     *  005C4183   83C4 0C          ADD ESP,0xC
     *  005C4186   5F               POP EDI
     *  005C4187   5E               POP ESI
     *  005C4188   B0 01            MOV AL,0x1
     *  005C418A   5B               POP EBX
     *  005C418B   C2 0400          RETN 0x4
     *  005C418E   CC               INT3
     */
    static bool InsertSystem43NewHook(ULONG startAddress, ULONG stopAddress, LPCSTR hookName)
    {
        const BYTE bytes[] = {
          0xe8, XX4,              // 004eeb34   e8 67cb0100      call .0050b6a0  ; jichi: hook here, text on the top of the stack
          0x39,0x6c,0x24, 0x28,   // 004eeb39   396c24 28        cmp dword ptr ss:[esp+0x28],ebp
          0x72, 0x0d,             // 004eeb3d   72 0d            jb short .004eeb4c
          0x8b,0x4c,0x24, 0x14,   // 004eeb3f   8b4c24 14        mov ecx,dword ptr ss:[esp+0x14]
          0x51,                   // 004eeb43   51               push ecx
          0xe8 //, XX4,           // 004eeb44   e8 42dc1900      call .0068c78b
        };
        enum { addr_offset = 0 };
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
        //GROWL_DWORD(addr);
        if (!addr) {
            ConsoleOutput("vnreng:System43+: pattern not found");
            return false;
        }

        //addr = *(DWORD *)(addr+1) + addr + 5; // change to hook to the actual address of function being called

        HookParam hp = {};
        hp.address = addr;
        hp.type = NO_CONTEXT | USING_STRING | USING_SPLIT | SPLIT_INDIRECT;
        //hp.type = NO_CONTEXT|USING_STRING|FIXING_SPLIT;
        hp.split_index = 0x10; // use [[esp]+0x10] to differentiate name and thread
        //hp.offset = 4 * 1; // text in arg1

        // Only name can be modified here, where the value of split is 0x6, and text in 0x2

        ConsoleOutput("vnreng: INSERT System43+");
        NewHook(hp, hookName);

        ConsoleOutput("vnreng:System43+: disable GDI hooks"); // disable hooking to TextOutA, which is cached

        return true;
    }

    bool InsertSystem43Hook()
    {
        //bool patched = Util::CheckFile(L"AliceRunPatch.dll");
        bool patched = ::GetModuleHandleA("AliceRunPatch.dll");
        // Insert new hook first
        bool ok = InsertSystem43OldHook(processStartAddress, processStopAddress, patched ? "AliceRunPatch43" : "System43");
        ok = InsertSystem43NewHook(processStartAddress, processStopAddress, "System43+") || ok;
        return ok;
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
        PcHooks::hookOtherPcFunctions(); // lstrlenA gives good hook too
      //SafeFillRange(processName, &base, &size);
      //size=size-base;
      //DWORD sig = 0x40c683; // add esi,0x40
      //i=processStartAddress+SearchPattern(processStartAddress,processStopAddress-processStartAddress,&sig,3);
        DWORD i;
        for (i = processStartAddress; i < processStopAddress - 4; i++) {
            DWORD sig = *(DWORD*)i & 0xffffff;
            if (0x40c683 == sig) // add esi,0x40
                break;
        }
        if (i < processStopAddress - 4)
            for (DWORD j = i - 0x200; i > j; i--)
                if (*(DWORD*)i == 0xff6acccc) { // find the function entry
                    HookParam hp = {};
                    hp.address = i + 2;
                    hp.offset = 8;
                    hp.split = -0x18;
                    hp.length_offset = 1;
                    hp.type = USING_SPLIT;
                    ConsoleOutput("vnreng: INSERT Aterlier KAGUYA");
                    NewHook(hp, "Atelier KAGUYA");
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
        for (DWORD i = processStartAddress + 0x1000; i < processStopAddress - 4; i++)
            if (*(WORD*)i == 0xa3c)  //cmp al, 0xA; je
                for (DWORD j = i; j < i + 0x100; j++) {
                    BYTE c = *(BYTE*)j;
                    if (c == 0xc3)
                        break;
                    if (c == 0xe8) {
                        DWORD k = *(DWORD*)(j + 1) + j + 5;
                        if (k > processStartAddress && k < processStopAddress) {
                            HookParam hp = {};
                            hp.address = k;
                            hp.offset = 0xc;
                            hp.split = -0x18;
                            hp.length_offset = 1;
                            hp.type = DATA_INDIRECT | USING_SPLIT;
                            ConsoleOutput("vnreng: INSERT CIRCUS#1");
                            NewHook(hp, "Circus1");
                            //RegisterEngineType(ENGINE_CIRCUS);
                            return true;
                        }
                    }
                }
        //break;
    //ConsoleOutput("Unknown CIRCUS engine");
        ConsoleOutput("vnreng:CIRCUS1: failed");
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
        for (DWORD i = processStartAddress + 0x1000; i < processStopAddress - 4; i++)
            if ((*(DWORD*)i & 0xffffff) == 0x75243c) { // cmp al, 24; je
                if (DWORD j = SafeFindEntryAligned(i, 0x80)) {
                    HookParam hp = {};
                    hp.address = j;
                    hp.offset = 0x8;
                    //hp.filter_fun = CharNewLineFilter; // \n\s* is used to remove new line
                    hp.type = USING_STRING;
                    ConsoleOutput("vnreng: INSERT CIRCUS#2");
                    //GROWL_DWORD(hp.address); // jichi 6/5/2014: 0x4201d0 for DC3
                    NewHook(hp, "Circus");
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
        void SpecialHookShina2(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            DWORD ptr = *(DWORD*)(esp_base - 0x20); ; // jichi: esi
            *split = ptr; // [esi]
            char* str = *(char**)(ptr + 0x160);
            strcpy(text_buffer, str);
            int skip = 0;
            for (str = text_buffer; *str; str++)
                if (str[0] == 0x5f) {   // jichi 7/10/2015: Skip _r (new line)
                    if (str[1] == 0x72)   // jichi 7/10/2015: Skip _t until /
                        str[0] = str[1] = 1;
                    else if (str[1] == 0x74) {
                        while (str[0] != 0x2f)
                            *str++ = 1;
                        *str = 1;
                    }
                }

            for (str = text_buffer; str[skip];)
                if (str[skip] == 1)
                    skip++;
                else {
                    str[0] = str[skip];
                    str++;
                }

            str[0] = 0;
            if (strcmp(text_buffer, text_buffer_prev) == 0)
                *len = 0;
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
        void SpecialHookShina1(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            static DWORD min_retaddr = -1;
            DWORD s = *(DWORD*)(esp_base + hp->split);
            if (s == 0 || (s & 0xffff) == 0xffff) { // only keep threads with 0 and -1 split
                if (s == 0 && retof(esp_base) <= min_retaddr) {
                    min_retaddr = retof(esp_base);
                    return;
                }
                *split = FIXED_SPLIT_VALUE;
                // Follow the same logic as the hook.
                *data = *(DWORD*)*data; // DATA_INDIRECT
                *len = LeadByteTable[*data & 0xff];
            }
        }

        // jichi 8/27/2013
        // Return ShinaRio version number
        // The head of Rio.ini usually looks like:
        //     [椎名里�v2.49]
        // This function will return 49 in the above case.
        //
        // Games from アトリエさく�do not have Rio.ini, but $procname.ini.
        int GetShinaRioVersion()
        {
            int ret = 0;
            HANDLE hFile = CreateFileW(L"RIO.INI", FILE_READ_DATA, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                size_t len = ::wcslen(processName);
                if (len > 3) {
                    wchar_t fname[MAX_PATH];
                    ::wcscpy(fname, processName);
                    fname[len - 1] = 'i';
                    fname[len - 2] = 'n';
                    fname[len - 3] = 'i';
                    hFile = CreateFileW(fname, FILE_READ_DATA, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                }
            }

            if (hFile != INVALID_HANDLE_VALUE) {
                //char *buffer,*version;//,*ptr;
                enum { BufferSize = 0x40 };
                char buffer[BufferSize]{};
                DWORD DUMMY;
                ReadFile(hFile, buffer, BufferSize, &DUMMY, nullptr);
                CloseHandle(hFile);
                //if (buffer[0] == '[') {
                buffer[0x3f] = 0; // jichi 8/24/2013: prevent strstr from overflow
                if (char* version = ::strstr(buffer, "v2."))
                    ::sscanf(version + 3, "%d", &ret); // +3 to skip "v2."
                //}
            }
            return ret;
        }

        bool IsSJIS(char* text)
        {
            for (int i = 0; i < 3; ++i) if (!IsDBCSLeadByte(text[i * 2])) return false;
            return true;
        }

    } // unnamed namespace

    // jichi 8/24/2013: Rewrite ShinaRio logic.
    // Test games: ���×Ｓ��　(PK), version ShinaRio 2.47
    bool InsertShinaHook()
    {
        int ver = GetShinaRioVersion();
        if (ver >= 50) {
            //trigger_fun = StackSearchingTrigger<GetGlyphOutlineA, NULL>;
            trigger_fun = [](LPVOID funcAddr, DWORD, DWORD stack)
            {
                bool ret = false;
                if (funcAddr != GetGlyphOutlineA) return false;
                for (int i = 0; i < 100; ++i)
                {
                    // Address of text is somewhere on stack in call to func. Search for it.
                    DWORD addr = *((DWORD*)stack + i);
                    //ConsoleOutput(std::to_string((DWORD)*addr).c_str());
                    if (IthGetMemoryRange((void*)addr, nullptr, nullptr) && strlen((char*)addr) > 9)
                    {
                        if (IsSJIS((char*)addr) || strstr((char*)addr, "_r"))
                        {
                            HookParam hp = {};
                            hp.type = DIRECT_READ;
                            hp.address = addr;
                            ConsoleOutput("Textractor: triggered: adding dynamic reader");
                            NewHook(hp, "READ");
                            ret = true;
                        }
                    };
                }
                return ret;
            };
            ConsoleOutput("Textractor: ShinaRio 2.50+: adding trigger");
            return true;
        }
        else if (ver >= 48) { // v2.48, v2.49
            HookParam hp = {};
            hp.address = (DWORD)::GetTextExtentPoint32A;
            hp.text_fun = SpecialHookShina2;
            hp.type = USING_STRING;
            ConsoleOutput("vnreng: INSERT ShinaRio > 2.47");
            NewHook(hp, "ShinaRio");
            //RegisterEngineType(ENGINE_SHINA);
            return true;

        }
        else if (ver > 40) { // <= v2.47. Older games like あやかしびと does not require hcode
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
            hp.address = (DWORD)::GetTextExtentPoint32A;
            hp.offset = arg2_lpString; // 0x8
            hp.length_offset = 1;
            hp.type = DATA_INDIRECT | USING_SPLIT;

            enum { sub_esp = 0xec81 }; // jichi: caller pattern: sub esp = 0x81,0xec
            if (DWORD s = Util::FindCallAndEntryBoth((DWORD)GetTextExtentPoint32A, processStopAddress - processStartAddress, processStartAddress, sub_esp)) {
                ConsoleOutput("vnreng: INSERT ShinaRio <= 2.47 dynamic split");
                hp.split = *(DWORD*)(s + 2) + 4;
                //RegisterEngineType(ENGINE_SHINA);
                NewHook(hp, "ShinaRio");

            }
            else {
                // jichi 3/13/2015: GetTextExtentPoint32A is not statically invoked in ���×Ｓ��　(PK)
                // See: http://sakuradite.com/topic/671
                // See: http://www.hongfire.com/forum/showthread.php/36807-AGTH-text-extraction-tool-for-games-translation/page347
                //
                // [Guilty+]Rin x Sen �Hakudaku Onna Kyoushi to Yaroudomo /HB8*0:44@0:GDI32.dll:GetTextExtentPoint32A /Ftext@4339A2:0;choices@4339A2:ffffff
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
                NewHook(hp, "ShinaRio2"); // jichi: mark as ShinaRio2 so that VNR is able to warn user about the text speed issue
            }
            return true;
        }
        ConsoleOutput("vnreng:ShinaRio: unknown version");
        return false;
    }

    bool InsertWaffleDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
    {
        ConsoleOutput("WaffleDynamic:triggered");
        if (addr != ::GetTextExtentPoint32A)
            return false;

        DWORD handler;
        __asm
        {
            mov eax, fs: [0]
            mov eax, [eax]
            mov eax, [eax]
            mov eax, [eax]
            mov eax, [eax]
            mov eax, [eax]
            mov ecx, [eax + 4]
            mov handler, ecx
        }

        union {
            DWORD i;
            BYTE* ib;
            DWORD* id;
        };
        // jichi 9/30/2013: Fix the bug in ITH logic where j is uninitialized
        for (i = processStartAddress + 0x1000; i < processStopAddress - 4; i++)
            if (*id == handler && *(ib - 1) == 0x68)
                if (DWORD t = SafeFindEntryAligned(i, 0x40)) {
                    HookParam hp = {};
                    hp.address = t;
                    hp.offset = 8;
                    hp.index = 4;
                    hp.length_offset = 1;
                    hp.type = DATA_INDIRECT;
                    ConsoleOutput("vnreng: INSERT Dynamic Waffle");
                    NewHook(hp, "Waffle");
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
    //      status = NtQueryVirtualMemory(GetCurrentProcess(),(PVOID)str,MemoryBasicInformation,&info,sizeof(info),0);
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
    //      if (retn > processStartAddress && retn < processStopAddress)
    //      {
    //        HookParam hp = {};
    //        hp.address = retn + *(DWORD*)(retn - 4);
    //        hp.length_offset = 1;
    //        hp.offset = -0x20;
    //        hp.index = 4;
    //        //hp.split = 0x1E8;
    //        hp.type = DATA_INDIRECT;
    //        NewHook(hp, "WAFFLE");
    //        //RegisterEngineType(ENGINE_WAFFLE);
    //        return true;
    //      }
    //
    //    }
    //
    //  }

    /** jichi 8/18/2015
     *  Sample game: 完全時間停止 体験版
     *  GDI text: TextOutA and GetTextExtentPoint32A
     */
    bool InsertWaffleHook()
    {
        bool found = false;
        for (DWORD i = processStartAddress + 0x1000; i < processStopAddress - 4; i++)
            if (*(DWORD*)i == 0xac68) {
                HookParam hp = {};
                hp.address = i;
                hp.length_offset = 1;
                hp.offset = 8;
                hp.index = 4;
                hp.split = 0x1e8;
                hp.type = DATA_INDIRECT | USING_SPLIT;
                ConsoleOutput("vnreng: INSERT WAFFLE");
                NewHook(hp, "WAFFLE");
                found = true;
            }

        /** new waffle? stolen from https://github.com/lgztx96
      *   test on 母三人とアナあそび https://vndb.org/v24214
      *   and 変態エルフ姉妹と真面目オーク https://vndb.org/v24215
      *   and いかにして俺の妻は孕んだか……  https://vndb.org/v26205
      *   and 俺の知らぬ間に彼女が… https://vndb.org/v27781
      */
        const BYTE bytes[] = {
            0x50,                     //50         push eax
            0x8b, 0xce,               //8BCE mov   ecx,esi
            0xc6, 0x45, 0xfc, 0x01,   //C645 FC 01 move byte ptr ss:[ebp-4],1
            0x89, 0x75, 0xd4,         //8975 D4    move dword ptr ss:[ebp-0x2c],esi
            0xe8, XX4,                //E8 ??      call ??
            0x8d, 0x45, 0xdc          //8D45 DC    lea eax,dword ptr ss:[ebp-0x24]
        };
        if (DWORD addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress))
        {
            HookParam hp = {};
            hp.address = addr;
            hp.offset = pusha_eax_off - 4;
            hp.index = 0x00;
            hp.split = 0x48;
            hp.length_offset = 1;
            hp.type = DATA_INDIRECT | USING_SPLIT;
            ConsoleOutput("Textractor: INSERT WAFFLE2");
            NewHook(hp, "WAFFLE2");
            found = true;
        }
        //ConsoleOutput("Probably Waffle. Wait for text.");
        if (!found) trigger_fun = InsertWaffleDynamicHook;
        return found;
        //ConsoleOutput("vnreng:WAFFLE: failed");
    }

    bool InsertTinkerBellHook()
    {
        //DWORD s1,s2,i;
        //DWORD ch=0x8141;
        DWORD i;
        WORD count;
        count = 0;
        HookParam hp = {};
        hp.length_offset = 1;
        hp.type = BIG_ENDIAN | NO_CONTEXT;
        for (i = processStartAddress; i < processStopAddress - 4; i++) {
            if (*(DWORD*)i == 0x8141) {
                BYTE t = *(BYTE*)(i - 1);
                if (t == 0x3d || t == 0x2d) {
                    hp.offset = -0x8;
                    hp.address = i - 1;
                }
                else if (*(BYTE*)(i - 2) == 0x81) {
                    t &= 0xf8;
                    if (t == 0xf8 || t == 0xe8) {
                        hp.offset = -8 - ((*(BYTE*)(i - 1) & 7) << 2);
                        hp.address = i - 2;
                    }
                }
                if (hp.address) {
                    char hook_name[0x20];
                    ::strcpy(hook_name, "TinkerBell"); // size = 0xa
                    hook_name[0xa] = '0' + count;
                    hook_name[0xb] = 0;
                    ConsoleOutput("vnreng:INSERT TinkerBell");
                    NewHook(hp, hook_name);
                    count++;
                    hp.address = 0;
                }
            }
        }
        if (count) return true;
        ConsoleOutput("vnreng:TinkerBell: failed");
        return false;
    }

    //  s1=SearchPattern(processStartAddress,processStopAddress-processStartAddress-4,&ch,4);
    //  if (s1)
    //  {
    //    for (i=s1;i>s1-0x400;i--)
    //    {
    //      if (*(WORD*)(processStartAddress+i)==0xec83)
    //      {
    //        hp.address=processStartAddress+i;
    //        NewHook(hp, "C.System");
    //        break;
    //      }
    //    }
    //  }
    //  s2=s1+SearchPattern(processStartAddress+s1+4,processStopAddress-s1-8,&ch,4);
    //  if (s2)
    //  {
    //    for (i=s2;i>s2-0x400;i--)
    //    {
    //      if (*(WORD*)(processStartAddress+i)==0xec83)
    //      {
    //        hp.address=processStartAddress+i;
    //        NewHook(hp, "TinkerBell");
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
        if (DWORD c = Util::FindCallOrJmpAbs((DWORD)::ExtTextOutA, processStopAddress - processStartAddress, processStartAddress, true))
            if (DWORD addr = Util::FindCallAndEntryRel(c, processStopAddress - processStartAddress, processStartAddress, fun)) {
                HookParam hp = {};
                hp.address = addr;
                hp.offset = 4;
                hp.type = USING_STRING;
                ConsoleOutput("vnreng:INSERT MBL-Furigana");
                NewHook(hp, "MBL-Furigana");
                ret = true;
            }
        if (DWORD c = Util::FindCallOrJmpAbs((DWORD)::GetGlyphOutlineA, processStopAddress - processStartAddress, processStartAddress, true))
            if (DWORD addr = Util::FindCallAndEntryRel(c, processStopAddress - processStartAddress, processStartAddress, fun)) {
                HookParam hp = {};
                hp.address = addr;
                hp.offset = 4;
                hp.split = -0x18;
                hp.length_offset = 1;
                hp.type = BIG_ENDIAN | USING_SPLIT;
                ConsoleOutput("vnreng:INSERT MBL");
                NewHook(hp, "MBL");
                ret = true;
            }
        if (!ret)
            ConsoleOutput("vnreng:MBL: failed");
        return ret;
    }

    /** jichi 7/26/2014: E.A.G.L.S engine for TechArts games (SQUEEZ, May-Be Soft)
     *  Sample games: [May-Be Soft] ちぽ�んじ� *  Should also work for SQUEEZ's 孕ませシリーズ
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
        hp.address = (DWORD)::GetGlyphOutlineA;
        hp.type = BIG_ENDIAN | USING_SPLIT; // the only difference is the split value
        hp.offset = arg2_uChar;
        hp.split = arg4_lpgm;
        //hp.split = arg7_lpmat2;
        hp.length_offset = 1;
        ConsoleOutput("vnreng:INSERT EAGLS");
        NewHook(hp, "EAGLS");
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
        DWORD entry = Util::FindCallAndEntryBoth((DWORD)TextOutA, processStopAddress - processStartAddress, processStartAddress, 0xec83);
        //GROWL_DWORD(entry);
        if (!entry) {
            ConsoleOutput("vnreng:YU-RIS: function entry does not exist");
            return false;
        }
        entry = Util::FindCallAndEntryRel(entry - 4, processStopAddress - processStartAddress, processStartAddress, 0xec83);
        //GROWL_DWORD(entry);
        if (!entry) {
            ConsoleOutput("vnreng:YU-RIS: function entry does not exist");
            return false;
        }
        entry = Util::FindCallOrJmpRel(entry - 4, processStopAddress - processStartAddress - 0x10000, processStartAddress + 0x10000, false);
        DWORD i,
            t = 0;
        //GROWL_DWORD(entry);
        ITH_TRY{ // jichi 12/27/2014
          for (i = entry - 4; i > entry - 0x100; i--)
            if (::IsBadReadPtr((LPCVOID)i, 4)) { // jichi 12/27/2014: might raise in new YU-RIS, 4 = sizeof(DWORD)
              ConsoleOutput("vnreng:YU-RIS: do not have read permission");
              return false;
            }
       else if (*(WORD*)i == 0xc085) {
      t = *(WORD*)(i + 2);
      if ((t & 0xff) == 0x76) {
        t = 4;
        break;
      }
else if ((t & 0xffff) == 0x860f) {
t = 8;
break;
}
}

        } ITH_EXCEPT{
          ConsoleOutput("vnreng:YU-RIS: illegal access exception");
          return false;
        }
            if (i == entry - 0x100) {
                ConsoleOutput("vnreng:YU-RIS: pattern not exist");
                return false;
            }
        //GROWL_DWORD2(i,t);
        HookParam hp = {};
        hp.address = i + t;
        hp.offset = -0x24;
        hp.split = -0x8;
        hp.type = USING_STRING | USING_SPLIT;
        ConsoleOutput("vnreng: INSERT YU-RIS");
        //GROWL_DWORD(hp.address);
        NewHook(hp, "YU-RIS");
        //RegisterEngineType(ENGINE_WHIRLPOOL);
        return true;
    }

    /** jichi 12/27/2014
     *
     *  Sample game: [Whirlpool] [150217] 鯨神�ヂ�アスヂ�ラ
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
        ULONG addr = MemDbg::findCallAddress((ULONG)::TextOutA, processStartAddress, processStopAddress);
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
        hp.address = addr;
        hp.type = USING_STRING | USING_SPLIT | NO_CONTEXT; // disable context that will cause thread split
        hp.offset = arg4_lpString;
        hp.split = arg6_split;

        ConsoleOutput("vnreng: INSERT YU-RIS 2");
        NewHook(hp, "YU-RIS2");
        return true;
    }

    bool InsertYurisHook()
    {
        return InsertYuris1Hook() || InsertYuris2Hook();
    }

    bool InsertCotophaHook1()
    {
        enum : DWORD { ins = 0xec8b55 }; // mov ebp,esp, sub esp,*  ; jichi 7/12/2014
        ULONG addr = MemDbg::findCallerAddress((ULONG)::GetTextMetricsA, ins, processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:Cotopha: pattern not exist");
            return false;
        }
        HookParam hp = {};
        hp.address = addr;
        hp.offset = 4;
        hp.split = -0x1c; // jichi: esp?
        hp.type = USING_UNICODE | USING_SPLIT | USING_STRING;
        ConsoleOutput("vnreng: INSERT Cotopha");
        NewHook(hp, "Cotopha");
        //RegisterEngineType(ENGINE_COTOPHA);
        return true;
    }

    bool InsertCotophaHook2()
    {
        if (void* addr = GetProcAddress(GetModuleHandleW(NULL), "eslHeapFree"))
        {
            HookParam hp = {};
            hp.address = (uintptr_t)addr;
            hp.offset = 8;
            hp.type = USING_UNICODE | USING_STRING;
            hp.filter_fun = [](void* data, DWORD* len, HookParam*, BYTE)
            {
                return std::wstring_view((wchar_t*)data, *len / sizeof(wchar_t)).find(L'\\') != std::wstring_view::npos;
            };
            ConsoleOutput("Textractor: INSERT Cotopha 2");
            NewHook(hp, "Cotopha2");
            return true;
        }
        return false;
    }

    bool InsertCotophaHook()
    {
        return InsertCotophaHook1() | InsertCotophaHook2();
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

    static void SpecialHookCatSystem3(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
    {
        //DWORD ch = *data = *(DWORD *)(esp_base + hp->offset); // arg2
        DWORD ch = *data = argof(2, esp_base);
        *len = LeadByteTable[(ch >> 8) & 0xff];  // BIG_ENDIAN
        *split = regof(edx, esp_base) >> 16;
    }

    bool InsertCatSystemHook()
    {
        //DWORD search=0x95EB60F;
        //DWORD j,i=SearchPattern(processStartAddress,processStopAddress-processStartAddress,&search,4);
        //if (i==0) return;
        //i+=processStartAddress;
        //for (j=i-0x100;i>j;i--)
        //  if (*(DWORD*)i==0xcccccccc) break;
        //if (i==j) return;
        //hp.address=i+4;
        //hp.offset=-0x8;
        //hp.index=4;
        //hp.split=4;
        //hp.split_index=0x18;
        //hp.type =BIG_ENDIAN|DATA_INDIRECT|USING_SPLIT|SPLIT_INDIRECT;
        //hp.length_offset=1;

        enum { beg = 0xff6acccc }; // jichi 7/12/2014: beginning of the function
        enum { addr_offset = 2 }; // skip two leading 0xcc
        ULONG addr = MemDbg::findCallerAddress((ULONG)::GetTextMetricsA, beg, processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:CatSystem2: pattern not exist");
            return false;
        }

        HookParam hp = {};
        hp.address = addr + addr_offset; // skip 1 push?
        hp.offset = 4 * 2; // text character is in arg2
        hp.length_offset = 1; // only 1 character

        // jichi 12/23/2014: Modify split for new catsystem
        bool newEngine = Util::CheckFile(L"cs2conf.dll");
        if (newEngine) {
            hp.text_fun = SpecialHookCatSystem3; // type not needed
            NewHook(hp, "CatSystem3");
            ConsoleOutput("vnreng: INSERT CatSystem3");
        }
        else {
            hp.type = BIG_ENDIAN | USING_SPLIT;
            hp.split = pusha_edx_off - 4; // -0x10
            NewHook(hp, "CatSystem2");
            ConsoleOutput("vnreng: INSERT CatSystem2");
        }
        //RegisterEngineType(ENGINE_CATSYSTEM);
        return true;
    }

    bool InsertNitroplusHook()
    {
        const BYTE bytes[] = { 0xb0, 0x74, 0x53 };
        DWORD addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:Nitroplus: pattern not exist");
            return false;
        }
        enum : WORD { sub_esp = 0xec83 }; // caller pattern: sub esp = 0x83,0xec
        BYTE b = *(BYTE*)(addr + 3) & 3;
        while (*(WORD*)addr != sub_esp)
            addr--;
        HookParam hp = {};
        hp.address = addr;
        hp.offset = -0x14 + (b << 2);
        hp.length_offset = 1;
        hp.type = BIG_ENDIAN;
        ConsoleOutput("vnreng: INSERT Nitroplus");
        NewHook(hp, "Nitroplus");
        //RegisterEngineType(ENGINE_Nitroplus);
        return true;
    }

    /**
     *  Jazzinghen 23/05/2020: Add TokyoNecro hook
     *
     *  [Nitroplus] 東京Necro 1.01 - Text boxes hook
     *
     *  Hook code: HS-14*8@B5420:TokyoNecro.exe
     *
     *  Debug method:
     *  Found memory location where the text was written, then used hardware break on write.
     *  After that found the function that writes the text in, found that the memory pointed
     *  contains more than just the text. Followed the call stack "upwards" until a function
     *  that handles only the text copy is found.
     *
     *  Disassembled code:
     *  TokyoNecro.exe+B5420 - 55                - push ebp                  ; place to hook
     *  TokyoNecro.exe+B5421 - 8B EC             - mov ebp,esp
     *  TokyoNecro.exe+B5423 - 6A FF             - push -01
     *  TokyoNecro.exe+B5425 - 68 E8613000       - push TokyoNecro.exe+1961E8
     *  TokyoNecro.exe+B542A - 64 A1 00000000    - mov eax,fs:[00000000]
     *  TokyoNecro.exe+B5430 - 50                - push eax
     *  TokyoNecro.exe+B5431 - 64 89 25 00000000 - mov fs:[00000000],esp
     *  TokyoNecro.exe+B5438 - 83 EC 1C          - sub esp,1C
     *  TokyoNecro.exe+B543B - 8B 55 08          - mov edx,[ebp+08]
     *  TokyoNecro.exe+B543E - 53                - push ebx
     *  TokyoNecro.exe+B543F - 56                - push esi
     *  TokyoNecro.exe+B5440 - 8B C2             - mov eax,edx
     *  TokyoNecro.exe+B5442 - 57                - push edi
     *  TokyoNecro.exe+B5443 - 8B D9             - mov ebx,ecx
     *  TokyoNecro.exe+B5445 - C7 45 EC 0F000000 - mov [ebp-14],0000000F
     *  TokyoNecro.exe+B544C - C7 45 E8 00000000 - mov [ebp-18],00000000
     *  TokyoNecro.exe+B5453 - C6 45 D8 00       - mov byte ptr [ebp-28],00
     *  TokyoNecro.exe+B5457 - 8D 70 01          - lea esi,[eax+01]
     *  TokyoNecro.exe+B545A - 8D 9B 00000000    - lea ebx,[ebx+00000000]
     *  TokyoNecro.exe+B5460 - 8A 08             - mov cl,[eax]
     *  TokyoNecro.exe+B5462 - 40                - inc eax
     *  TokyoNecro.exe+B5463 - 84 C9             - test cl,cl
     *  TokyoNecro.exe+B5465 - 75 F9             - jne TokyoNecro.exe+B5460
     *  TokyoNecro.exe+B5467 - 2B C6             - sub eax,esi
     *  TokyoNecro.exe+B5469 - 52                - push edx
     *  TokyoNecro.exe+B546A - 8B F8             - mov edi,eax                ▷ Search
     *  TokyoNecro.exe+B546C - 8D 75 D8          - lea esi,[ebp-28]           |
     *  TokyoNecro.exe+B546F - E8 6CE1F4FF       - call TokyoNecro.exe+35E0   ▷
     *
     *  Notes:
     *
     *  There's more data above due to the fact that the start of the function is very
     *  common and it was hooking a wrong function.
     *
     *  The text is contained into the memory location at [esp+04] when hooking the
     *  code at TokyoNecro.exe+B5420
     *
     *  If the game is hooked right at the main menu it will also catch the real time clock
     *  rendered there.
     */

    namespace TokyoNecro {

        const BYTE funcSig[] = { 0x55, 0x8b, 0xec };

        bool TextHook() {

            const BYTE bytecodes[] = {
                0x8B, 0xF8,                               // 8B F8             - mov edi,eax
                0x8D, 0x75, 0xD8,                         // 8D 75 D8          - lea esi,[ebp-28]
                0xE8, 0x6C, 0xE1, 0xF4, 0xFF,             // E8 6CE1F4FF       - call TokyoNecro.exe+35E0
            };
            ULONG addr = MemDbg::findBytes(bytecodes, sizeof(bytecodes), processStartAddress, processStopAddress);
            if (addr == 0) {
                ConsoleOutput("Textractor:TokyoNecro: pattern not found");
                return false;
            }

            // Look for the start of the function
            const ULONG function_start = MemDbg::findEnclosingAlignedFunction(addr);
            if (memcmp((void*)function_start, funcSig, sizeof(funcSig)) != 0) {
                ConsoleOutput("Textractor: TokyoNecro: function start not found");
                return false;
            }

            HookParam hp = {};
            hp.address = function_start;
            // The memory address is held at [ebp+08] at TokyoNecro.exe+B543B, meaning that at
            // the start of the function it's right above the stack pointer. Since there's no
            // way to do an operation on the value of a register BEFORE dereferencing (e.g.
            // (void*)(esp+4) instead of ((void*)esp)+4) we have to go up the stack instead of
            // using the data in the registers
            hp.offset = 0x4;
            hp.type = USING_STRING;
            ConsoleOutput("Textractor: INSERT TokyoNecroText");
            NewHook(hp, "TokyoNecroText");
            return true;
        }

        /**
         * [Nitroplus] 東京Necro 1.01 - Database/Encyclopedia hook
         *
         * Hook code: HS4*@B5380:tokyonecro.exe
         *
         * TokyoNecro.exe+B5380 - 55                - push ebp                  ; Location to hook
         * TokyoNecro.exe+B5381 - 8B EC             - mov ebp,esp
         * TokyoNecro.exe+B5383 - 6A FF             - push -01
         * TokyoNecro.exe+B5385 - 68 E8618E00       - push TokyoNecro.exe+1961E8
         * TokyoNecro.exe+B538A - 64 A1 00000000    - mov eax,fs:[00000000]
         * TokyoNecro.exe+B5390 - 50                - push eax
         * TokyoNecro.exe+B5391 - 64 89 25 00000000 - mov fs:[00000000],esp
         * TokyoNecro.exe+B5398 - 83 EC 1C          - sub esp,1C
         * TokyoNecro.exe+B539B - 8B 55 08          - mov edx,[ebp+08]
         * TokyoNecro.exe+B539E - 53                - push ebx
         * TokyoNecro.exe+B539F - 56                - push esi
         * TokyoNecro.exe+B53A0 - 8B C2             - mov eax,edx
         * TokyoNecro.exe+B53A2 - 57                - push edi
         * TokyoNecro.exe+B53A3 - 8B D9             - mov ebx,ecx
         * TokyoNecro.exe+B53A5 - C7 45 EC 0F000000 - mov [ebp-14],0000000F
         * TokyoNecro.exe+B53AC - C7 45 E8 00000000 - mov [ebp-18],00000000
         * TokyoNecro.exe+B53B3 - C6 45 D8 00       - mov byte ptr [ebp-28],00
         * TokyoNecro.exe+B53B7 - 8D 70 01          - lea esi,[eax+01]
         * TokyoNecro.exe+B53BA - 8D 9B 00000000    - lea ebx,[ebx+00000000]
         * TokyoNecro.exe+B53C0 - 8A 08             - mov cl,[eax]
         * TokyoNecro.exe+B53C2 - 40                - inc eax
         * TokyoNecro.exe+B53C3 - 84 C9             - test cl,cl
         * TokyoNecro.exe+B53C5 - 75 F9             - jne TokyoNecro.exe+B53C0
         * TokyoNecro.exe+B53C7 - 2B C6             - sub eax,esi
         * TokyoNecro.exe+B53C9 - 52                - push edx
         * TokyoNecro.exe+B53CA - 8B F8             - mov edi,eax               ▷ Search
         * TokyoNecro.exe+B53CC - 8D 75 D8          - lea esi,[ebp-28]          |
         * TokyoNecro.exe+B53CF - E8 0CE2F4FF       - call TokyoNecro.exe+35E0  ▷
         *
         *
         */

        bool DatabaseHook()
        {
            const BYTE bytecodes[] = {
                0x8B, 0xF8,                               // 8B F8             - mov edi,eax
                0x8D, 0x75, 0xD8,                         // 8D 75 D8          - lea esi,[ebp-28]
                0xE8, 0x0C, 0xE2, 0xF4, 0xFF,             // E8 6CE1F4FF       - call TokyoNecro.exe+35E0
            };
            ULONG addr = MemDbg::findBytes(bytecodes, sizeof(bytecodes), processStartAddress, processStopAddress);
            if (addr == 0) {
                ConsoleOutput("vnreng:TokyoNecro: pattern not found");
                return false;
            }

            // Look for the start of the function
            const ULONG function_start = MemDbg::findEnclosingAlignedFunction(addr);
            if (memcmp((void*)function_start, funcSig, sizeof(funcSig)) != 0) {
                ConsoleOutput("Textractor: TokyoNecro: function start not found");
                return false;
            }

            HookParam hp = {};
            hp.address = function_start;
            hp.offset = 0x4;
            hp.type = USING_STRING;
            NewHook(hp, "TokyoNecroDatabase");
            ConsoleOutput("vnreng: INSERT TokyoNecroDatabase");
            return true;
        }

    } // namespace TokyoNecro

    bool InsertTokyoNecroHook()
    {
        TokyoNecro::DatabaseHook();
        return TokyoNecro::TextHook();
    }

    // jichi 6/21/2015
    namespace { // unnamed

        void SpecialHookRetouch1(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            DWORD text = argof(1, esp_base);
            *data = text;
            *len = ::strlen((LPCSTR)text);
            *split =
                regof(eax, esp_base) == 0 ? FIXED_SPLIT_VALUE * 2 : // name
                regof(ebx, esp_base) == 0 ? FIXED_SPLIT_VALUE * 1 : // scenario
                FIXED_SPLIT_VALUE * 3; // other
        }

        bool InsertRetouch1Hook()
        {
            HMODULE hModule = ::GetModuleHandleA("resident.dll");
            if (!hModule) {
                ConsoleOutput("vnreng:Retouch: failed, dll handle not loaded");
                return false;
            }
            // private: bool __thiscall RetouchPrintManager::printSub(char const *,class UxPrintData &,unsigned long)	0x10050650	0x00050650	2904 (0xb58)	resident.dll	C:\Local\箱庭ロジヂ�\resident.dll	Exported Function
            const char* sig = "?printSub@RetouchPrintManager@@AAE_NPBDAAVUxPrintData@@K@Z";
            DWORD addr = (DWORD)::GetProcAddress(hModule, sig);
            if (!addr) {
                ConsoleOutput("vnreng:Retouch: failed, procedure not found");
                return false;
            }

            HookParam hp = {};
            hp.address = addr;
            hp.offset = 4;
            hp.type = USING_STRING | NO_CONTEXT;
            hp.text_fun = SpecialHookRetouch1;
            ConsoleOutput("vnreng: INSERT Retouch");
            NewHook(hp, "Retouch");
            return true;
        }

        bool InsertRetouch2Hook()
        {
            HMODULE hModule = ::GetModuleHandleA("resident.dll");
            if (!hModule) {
                ConsoleOutput("vnreng:Retouch2: failed, dll handle not loaded");
                return false;
            }
            // private: void __thiscall RetouchPrintManager::printSub(char const *,unsigned long,int &,int &)	0x10046560	0x00046560	2902 (0xb56)	resident.dll	C:\Local\箱庭ロジヂ�\resident.dll	Exported Function
            const char* sig = "?printSub@RetouchPrintManager@@AAEXPBDKAAH1@Z";
            DWORD addr = (DWORD)::GetProcAddress(hModule, sig);
            if (!addr) {
                ConsoleOutput("vnreng:Retouch2: failed, procedure not found");
                return false;
            }

            HookParam hp = {};
            hp.address = addr;
            hp.offset = 4;
            hp.type = USING_STRING;
            ConsoleOutput("vnreng: INSERT Retouch");
            NewHook(hp, "Retouch");
            return true;
        }

    } // unnamed namespace
    bool InsertRetouchHook()
    {
        bool ok = InsertRetouch1Hook();
        ok = InsertRetouch2Hook() || ok;
        return ok;
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
            DWORD i = SearchPattern(processStartAddress, processStopAddress - processStartAddress, &sig1, sig1_size);
            if (!i) {
                ConsoleOutput("vnreng:MalieHook1: pattern i not exist");
                return false;
            }

            const WORD sig2 = 0xc383;
            enum { sig2_size = 2 };
            DWORD j = i + processStartAddress + sig1_size;
            i = SearchPattern(j, processStopAddress - j, &sig2, sig2_size);
            //if (!j)
            if (!i) { // jichi 8/19/2013: Change the condition fro J to I
                ConsoleOutput("vnreng:MalieHook1: pattern j not exist");
                return false;
            }
            HookParam hp = {};
            hp.address = j + i;
            hp.offset = -0x14;
            hp.index = -0x8;
            hp.split = -0x14;
            hp.split_index = 0x10;
            hp.length_offset = 1;
            hp.type = USING_UNICODE | USING_SPLIT | DATA_INDIRECT | SPLIT_INDIRECT;
            ConsoleOutput("vnreng: INSERT MalieHook1");
            NewHook(hp, "Malie");
            //RegisterEngineType(ENGINE_MALIE);
            return true;
        }

        DWORD malie_furi_flag_; // jichi 8/20/2013: Make it global so that it can be reset
        void SpecialHookMalie(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            DWORD ch = *(DWORD*)(esp_base - 0x8) & 0xffff,
                ptr = *(DWORD*)(esp_base - 0x24);
            *data = ch;
            *len = 2;
            if (malie_furi_flag_) {
                DWORD index = *(DWORD*)(esp_base - 0x10);
                if (*(WORD*)(ptr + index * 2 - 2) < 0xa)
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
            const BYTE bytes[] = { 0x66,0x3d,0x1,0x0 };
            DWORD start = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
            if (!start) {
                ConsoleOutput("vnreng:MalieHook2: pattern not exist");
                return false;
            }
            BYTE* ptr = (BYTE*)start;
            while (true) {
                if (*(WORD*)ptr == 0x3d66) {
                    ptr += 4;
                    if (ptr[0] == 0x75) {
                        ptr += ptr[1] + 2;
                        continue;
                    }
                    if (*(WORD*)ptr == 0x850f) {
                        ptr += *(DWORD*)(ptr + 2) + 6;
                        continue;
                    }
                }
                break;
            }
            malie_furi_flag_ = 0; // reset old malie flag
            HookParam hp = {};
            hp.address = (DWORD)ptr + 4;
            hp.offset = -8;
            hp.length_offset = 1;
            hp.text_fun = SpecialHookMalie;
            hp.type = USING_SPLIT | USING_UNICODE | NO_CONTEXT;
            hp.type = NO_CONTEXT;
            ConsoleOutput("vnreng: INSERT MalieHook2");
            NewHook(hp, "Malie");
            //RegisterEngineType(ENGINE_MALIE);
            ConsoleOutput("vnreng:Malie2: disable GDI hooks");

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
        void SpecialHookMalie2(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            //CC_UNUSED(data);
            //*len = GetHookDataLength(*hp, esp_base, (DWORD)data);
            *len = 2;

            DWORD s1 = *(DWORD*)(esp_base + 0xc), // base split, which is stable
                s2 = (*(DWORD*)esp_base); // used to split out furigana, but un stable
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
            ULONG range1 = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
            ULONG addr = MemDbg::findBytes(bytes1, sizeof(bytes1), processStartAddress, processStartAddress + range1);
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
            hp.address = addr;
            hp.offset = -8; // pusha_eax_off - 4
            hp.length_offset = 1;
            //hp.split = 0xc; // jichi 12/17/2013: Subcontext removed
            //hp.split = -0xc; // jichi 12/17/2013: This could split the furigana, but will mess up the text
            //hp.type = USING_SPLIT|USING_UNICODE|NO_CONTEXT;
            // jichi 12/17/2013: Need extern func for Electro Arms
            // Though the hook parameter is quit similar to Malie, the original extern function does not work
            hp.type = USING_SPLIT | NO_CONTEXT | USING_UNICODE;
            hp.text_fun = SpecialHookMalie2;
            ConsoleOutput("vnreng: INSERT Malie2");
            NewHook(hp, "Malie2");

            //GROWL_DWORD2(hp.address, reladdr);
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
                    }
                    else if (p[0] >= 0xa) // ltrim illegal characters less than 0xa
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
                        if (p[-1] >= L'0' && p[-1] <= L'9' && p[-1 - 7] == L'_')
                            p -= 9;
                        else
                            return p;
                    }
            return nullptr;
        }

        // Example section in memory:
        // 0D7D7E00  07 00 08 00 76 00 5F 00 7A 00 65 00 70 00 30 00  v_zep0
        // 0D7D7E10  30 00 37 00 35 00 00 00 0C 30 42 30 41 30 01 30  075.「あぁ�// 0D7D7E20  41 30 26 20 26 20 07 00 09 00 07 00 06 00 07 00  ぁ…….
        // 0D7D7E30  08 00 76 00 5F 00 7A 00 65 00 70 00 30 00 30 00  v_zep00
        // 0D7D7E40  37 00 36 00 00 00 46 30 01 30 42 30 01 30 41 30  76.぀�あ、ぁ
        // 0D7D7E50  41 30 41 30 26 20 26 20 26 20 26 20 01 30 63 30  ぁぁ…………、っ
        // 0D7D7E60  07 00 09 00 0D 30 07 00 06 00 0A 00 0A 00 00 30  .�..
        // 0D7D7E70  16 60 44 30 01 30 16 60 44 30 01 30 4A 30 5E 30  怖い、怖い、お�// 0D7D7E80  7E 30 57 30 44 30 02 30 55 4F 4C 30 16 60 44 30  ましい。何が怖い
        // 0D7D7E90  6E 30 4B 30 55 30 48 30 01 30 06 52 4B 30 89 30  のかさえ、�から
        // 0D7D7EA0  6A 30 44 30 02 30 07 00 06 00 0A 00 00 30 8B 89  な぀.　�// 0D7D7EB0  8B 30 6A 30 88 30 02 30 8B 89 8B 30 6A 30 02 30  るなよ。見るな�// 0D7D7EC0  07 00 06 00 8B 89 8B 30 6A 30 01 30 8B 89 8B 30  見るな、見る
        // 0D7D7ED0  6A 30 8B 89 8B 30 6A 30 8B 89 8B 30 6A 30 01 30  な見るな見るな�// 0D7D7EE0  1F 75 4D 30 66 30 66 30 AA 60 44 30 4B 30 88 30  生きてて悪ぁ��// 0D7D7EF0  02 30 C5 60 51 30 6A 30 44 30 63 30 66 30 07 00  。情けなぁ�て
        // 0D7D7F00  01 00 E4 55 0A 00 8F 30 89 30 00 00 46 30 6A 30  嗤.わら.ぁ�
        // 0D7D7F10  88 30 02 30 07 00 06 00 BE 7C 00 4E 6F 67 6A 30  よ�精一杯な
        // 0D7D7F20  93 30 60 30 8B 89 03 90 57 30 66 30 4F 30 8C 30  んだ見送�てくれ
        // 0D7D7F30  02 30 4A 30 58 98 44 30 57 30 7E 30 59 30 01 30  。お願いします�// 0D7D7F40  60 30 4B 30 89 30 69 30 46 30 4B 30 5D 30 6E 30  �からどぁ�そ�
        // 0D7D7F50  EE 76 92 30 84 30 81 30 66 30 01 30 4F 30 60 30  目をやめて、く�
        // 0D7D7F60  55 30 44 30 01 30 5D 30 93 30 6A 30 02 30 07 00  さい、そんな�
        // 0D7D7F70  06 00 0A 00 00 30 07 00 01 00 BA 87 50 5B 0A 00  .　螺�
        // 0D7D7F80  59 30 4C 30 00 00 8B 30 88 30 46 30 6A 30 EE 76  すが.るよぁ�目
        // 0D7D7F90  67 30 00 25 00 25 07 00 06 00 BF 30 01 30 B9 30  で──タ、ス
        // 0D7D7FA0  01 30 B1 30 01 30 C6 30 01 30 6A 30 93 30 66 30  、ケ、テ、なんて
        // 0D7D7FB0  02 30 07 00 06 00 00 00 00 00 00 00 00 00 00 00  �.....
        // 0D7D7FC0  FC D8 C0 22 00 00 00 80 74 00 00 00 00 00 00 00  .耀t...
        //
        // Return the end of the line
        LPCWSTR _Malie3GetEOL(LPCWSTR p)
        {
            if (p)
                for (int count = 0; count < _MALIE3_MAX_LENGTH; count++,
                    p++)
                    switch (*p) {
                    case 0:
                    case 0xa: // stop at \0, or \n where the text after 0xa is furigana
                        return p;
                    case 0x7:
                        // \x07\x00\x01\x00 is used to split furigana, which we want to keep
                        // \x07\x00\x04\x00 is used to split sentences, observed in シルヴァリオ ヴェンヂ�ヂ�
                        // \x07\x00\x06\x00 is used to split paragraph, observed in シルヴァリオ ヴェンヂ�ヂ�
                        if (p[1] < 0xa && p[1] != 0x1)
                            return p;
                    }
            return nullptr;
        }

        /**
         *  jichi 3/8/2014: Add hook for 相州戦神館學�八命陣
         *  See: http://sakuradite.com/topic/157
         *  check 0x5b51ed for ecx+edx*2
         *  Also need to skip furigana.
         */

        void SpecialHookMalie3(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            //CC_UNUSED(split);
            DWORD ecx = regof(ecx, esp_base), // *(DWORD *)(esp_base + pusha_ecx_off - 4),
                edx = regof(edx, esp_base); // *(DWORD *)(esp_base + pusha_edx_off - 4);
          //*data = ecx + edx*2; // [ecx+edx*2];
          //*len = wcslen((LPCWSTR)data) << 2;
          // There are garbage characters
            LPCWSTR start = _Malie3LTrim((LPCWSTR)(ecx + edx * 2)),
                stop = _Malie3RTrim(_Malie3GetEOL(start));
            *data = (DWORD)start;
            *len = max(0, stop - start) * 2;
            *split = FIXED_SPLIT_VALUE;
            //GROWL_DWORD5((DWORD)start, (DWORD)stop, *len, (DWORD)*start, (DWORD)_Malie3GetEOL(start));
        }

        /**
         *  jichi 8/20/2013: Add hook for 相州戦神館學�八命陣
         *  See: http://sakuradite.com/topic/157
         *  Credits: @ok123
         *
         *  Debugging method: insert hardware breakpoint into text
         *  There are four matches of text in the memory
         *
         *  Sample game: シルヴァリオ ヴェンヂ�ヂ�
         *  0065478B   90               NOP
         *  0065478C   90               NOP
         *  0065478D   90               NOP
         *  0065478E   90               NOP
         *  0065478F   90               NOP
         *  00654790   8B4424 04        MOV EAX,DWORD PTR SS:[ESP+0x4]
         *  00654794   56               PUSH ESI
         *  00654795   57               PUSH EDI
         *  00654796   8B50 08          MOV EDX,DWORD PTR DS:[EAX+0x8]
         *  00654799   8B08             MOV ECX,DWORD PTR DS:[EAX]
         *  0065479B   33F6             XOR ESI,ESI
         *  0065479D   66:8B3451        MOV SI,WORD PTR DS:[ECX+EDX*2]  ; jichi: text accessed here
         *  006547A1   42               INC EDX
         *  006547A2   8970 04          MOV DWORD PTR DS:[EAX+0x4],ESI
         *  006547A5   8950 08          MOV DWORD PTR DS:[EAX+0x8],EDX
         *  006547A8   8B50 04          MOV EDX,DWORD PTR DS:[EAX+0x4]
         *  006547AB   83FA 01          CMP EDX,0x1
         *  006547AE   75 2C            JNZ SHORT malie.006547DC
         *  006547B0   8B50 08          MOV EDX,DWORD PTR DS:[EAX+0x8]
         *  006547B3   33F6             XOR ESI,ESI
         *  006547B5   66:8B3451        MOV SI,WORD PTR DS:[ECX+EDX*2]
         *  006547B9   42               INC EDX
         *  006547BA   8970 04          MOV DWORD PTR DS:[EAX+0x4],ESI
         *  006547BD   33F6             XOR ESI,ESI
         *  006547BF   8950 08          MOV DWORD PTR DS:[EAX+0x8],EDX
         *  006547C2   66:8B3451        MOV SI,WORD PTR DS:[ECX+EDX*2]
         *  006547C6   8970 04          MOV DWORD PTR DS:[EAX+0x4],ESI
         *  006547C9   42               INC EDX
         *  006547CA   33F6             XOR ESI,ESI
         *  006547CC   8950 08          MOV DWORD PTR DS:[EAX+0x8],EDX
         *  006547CF   66:8B3451        MOV SI,WORD PTR DS:[ECX+EDX*2]
         *  006547D3   42               INC EDX
         *  006547D4   8970 04          MOV DWORD PTR DS:[EAX+0x4],ESI
         *  006547D7   8950 08          MOV DWORD PTR DS:[EAX+0x8],EDX
         *  006547DA  ^EB BF            JMP SHORT malie.0065479B
         *  006547DC   83FA 02          CMP EDX,0x2
         *  006547DF   0F84 59010000    JE malie.0065493E
         *  006547E5   83FA 03          CMP EDX,0x3
         *  006547E8   75 12            JNZ SHORT malie.006547FC
         *  006547EA   8B50 08          MOV EDX,DWORD PTR DS:[EAX+0x8]
         *  006547ED   33F6             XOR ESI,ESI
         *  006547EF   66:8B3451        MOV SI,WORD PTR DS:[ECX+EDX*2]
         *  006547F3   42               INC EDX
         *  006547F4   8970 04          MOV DWORD PTR DS:[EAX+0x4],ESI
         *  006547F7   8950 08          MOV DWORD PTR DS:[EAX+0x8],EDX
         *  006547FA  ^EB 9F            JMP SHORT malie.0065479B
         *  006547FC   83FA 04          CMP EDX,0x4
         *  006547FF   0F84 39010000    JE malie.0065493E
         *  00654805   83FA 07          CMP EDX,0x7
         *  00654808   0F85 27010000    JNZ malie.00654935
         *  0065480E   8B50 08          MOV EDX,DWORD PTR DS:[EAX+0x8]
         *  00654811   33F6             XOR ESI,ESI
         *  00654813   66:8B3451        MOV SI,WORD PTR DS:[ECX+EDX*2]
         *  00654817   8970 04          MOV DWORD PTR DS:[EAX+0x4],ESI
         *  0065481A   8D72 01          LEA ESI,DWORD PTR DS:[EDX+0x1]
         *  0065481D   8B50 04          MOV EDX,DWORD PTR DS:[EAX+0x4]
         *  00654820   8970 08          MOV DWORD PTR DS:[EAX+0x8],ESI
         *  00654823   8D7A FF          LEA EDI,DWORD PTR DS:[EDX-0x1]
         *  00654826   83FF 3B          CMP EDI,0x3B
         *  00654829  ^0F87 79FFFFFF    JA malie.006547A8
         *  0065482F   33D2             XOR EDX,EDX
         *  00654831   8A97 9C496500    MOV DL,BYTE PTR DS:[EDI+0x65499C]
         *  00654837   FF2495 80496500  JMP DWORD PTR DS:[EDX*4+0x654980]
         *  0065483E   8B50 0C          MOV EDX,DWORD PTR DS:[EAX+0xC]
         *  00654841   85D2             TEST EDX,EDX
         *  00654843   0F8F 2B010000    JG malie.00654974
         *  00654849   33D2             XOR EDX,EDX
         *  0065484B   66:8B1471        MOV DX,WORD PTR DS:[ECX+ESI*2]
         *  0065484F   46               INC ESI
         *  00654850   85D2             TEST EDX,EDX
         *  00654852   8950 04          MOV DWORD PTR DS:[EAX+0x4],EDX
         *  00654855   8970 08          MOV DWORD PTR DS:[EAX+0x8],ESI
         *  00654858   0F84 E0000000    JE malie.0065493E
         *  0065485E   8B50 08          MOV EDX,DWORD PTR DS:[EAX+0x8]
         *  00654861   33F6             XOR ESI,ESI
         *  00654863   66:8B3451        MOV SI,WORD PTR DS:[ECX+EDX*2]
         *  00654867   42               INC EDX
         *  00654868   8950 08          MOV DWORD PTR DS:[EAX+0x8],EDX
         *  0065486B   8BD6             MOV EDX,ESI
         *  0065486D   85D2             TEST EDX,EDX
         *  0065486F   8970 04          MOV DWORD PTR DS:[EAX+0x4],ESI
         *  00654872  ^75 EA            JNZ SHORT malie.0065485E
         *  00654874   8B50 08          MOV EDX,DWORD PTR DS:[EAX+0x8]
         */
        bool InsertMalie3Hook()
        {
            // i.e. 8b44240456578b50088b0833f6668b345142
            const BYTE bytes[] = {
                // 0x90 nop
                0x8b,0x44,0x24, 0x04,   // 5b51e0  mov eax,dword ptr ss:[esp+0x4]   ; jichi: function starts
                0x56,                   // 5b51e4  push esi
                0x57,                   // 5b51e5  push edi
                0x8b,0x50, 0x08,        // 5b51e6  mov edx,dword ptr ds:[eax+0x8]
                0x8b,0x08,              // 5b51e9  mov ecx,dword ptr ds:[eax]
                0x33,0xf6,              // 5b51eb  xor esi,esi
                0x66,0x8b,0x34,0x51,    // 5b51ed  mov si,word ptr ds:[ecx+edx*2] // jichi: hook here
                0x42                    // 5b51f1  inc edx
            };
            enum { addr_offset = 0x5b51ed - 0x5b51e0 };
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("vnreng:Malie3: pattern not found");
                return false;
            }
            HookParam hp = {};
            hp.address = addr + addr_offset;
            //GROWL(hp.address);
            //hp.address = 0x5b51ed;
            //hp.address = 0x5b51f1;
            //hp.address = 0x5b51f2;
            // jichi 3/15/2015: Remove 0704 in シルヴァリオ ヴェンッ�タ
            hp.filter_fun = IllegalWideCharsFilter; // remove illegal control chars such as 0x07,0x01
            hp.text_fun = SpecialHookMalie3;
            hp.type = USING_SPLIT | NO_CONTEXT | USING_UNICODE;
            //hp.filter_fun = Malie3Filter;
            ConsoleOutput("vnreng: INSERT Malie3");
            NewHook(hp, "Malie3");
            ConsoleOutput("vnreng:Malie3: disable GDI hooks");

            return true;
        }

        bool InsertMalie4Hook()
        {
            // i.e. 50 8B 45 10 D9 9F ?? ?? ?? ?? 0F B7 04 58 50 51 E8 ?? ?? ?? ?? 8B 45 14 83 C4 10
            const BYTE bytes[] = {
              0x50,                   // 65904E | 50                       | push eax                                | mireado: pattern starts
              0x8B,0x45,0x10,			// 65904F | 8B 45 10                 | mov eax,dword ptr ss:[ebp+10]           |
              0xD9,0x9F,XX4,			// 659052 | D9 9F E8 6B 87 00        | fstp dword ptr ds:[edi+876BE8]          |
              0x0F,0xB7,0x04,0x58,	// 659058 | 0F B7 04 58              | movzx eax,word ptr ds:[eax+ebx*2]       |
              0x50,					// 65905C | 50                       | push eax                                |
              0x51,					// 65905D | 51                       | push ecx                                |
              0xE8,XX4, 				// 65905E | E8 DD 1D EA FF           | call malie.4FAE40                       | mireado: hook here
              0x8B,0x45,0x14,			// 659063 | 8B 45 14                 | mov eax,dword ptr ss:[ebp+14]           |
              0x83,0xC4,0x10			// 659066 | 83 C4 10                 | add esp,10                              |
            };
            enum { addr_offset = 0x65905E - 0x65904E };
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("vnreng:Malie4: pattern not found");
                return false;
            }

            HookParam hp = {};
            hp.address = addr + addr_offset;
            hp.offset = -8; // pusha_eax_off - 4
            hp.length_offset = 1;
            //hp.split = 0xc; // jichi 12/17/2013: Subcontext removed
            //hp.type = USING_SPLIT|USING_UNICODE|NO_CONTEXT;
            // jichi 12/17/2013: Need extern func for Electro Arms
            // Though the hook parameter is quit similar to Malie, the original extern function does not work
            hp.split = -0x10; // jichi 12/17/2013: This could split the furigana, but will mess up the text
            hp.type = USING_SPLIT | NO_CONTEXT | USING_UNICODE;
            ConsoleOutput("vnreng: INSERT Malie4");
            NewHook(hp, "Malie4");

            //GROWL_DWORD2(hp.address, reladdr);
            //RegisterEngineType(ENGINE_MALIE);
            return true;
        }

        // Artikash 1/19/2019: works on https://vndb.org/r52326
        bool InsertMalie5Hook()
        {
            const BYTE bytes[] = {
                0x8b, 0x49, 0x10, // mov ecx,[ecx+10]
                0x03, 0x08, // add ecx,[eax]
                0x51 // push ecx
            };

            if (DWORD addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress))
            {
                ConsoleOutput("Textractor: INSERT Malie5");
                HookParam hp = {};
                hp.address = addr + 5;
                hp.offset = pusha_ecx_off - 4;
                hp.type = USING_UNICODE | USING_STRING | NO_CONTEXT;
                NewHook(hp, "Malie5");
                return true;
            }

            ConsoleOutput("Textractor: Malie5 pattern not found");
            return false;
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
        if (Util::CheckFile(L"tools.dll"))
            return InsertMalieHook1(); // jichi 3/5/2015: For old light games such as Dies irae.

        else { // For old Malie games before 2015
          // jichi 8/20/2013: Add hook for sweet light engine
          // Insert both malie and malie2 hook.
            bool ok = false;

            // jichi 3/12/2015: Disable MalieHook2 which will crash シルヴァリオ ヴェンッ�タ
            //if (!Util::CheckFile(L"gdiplus.dll"))
            if (Util::CheckFile(L"System\\*")) { // Insert old Malie hook. There are usually System/cursor.cur
                ok = InsertMalieHook2() || ok;
                ok = InsertMalie2Hook() || ok; // jichi 8/20/2013
            }

            // The main disadvantage of Malie3 is that it cannot find character name
            ok = InsertMalie3Hook() || ok; // jichi 3/7/2014
            ok = InsertMalie4Hook() || ok;
            ok = InsertMalie5Hook() || ok;
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
        ULONG addr = MemDbg::findCallAddress((ULONG)::IsDBCSLeadByte, processStartAddress, processStopAddress);
        // no needed as first call to IsDBCSLeadByte is correct, but sig could be used for further verification
        //WORD sig = 0x51C3;
        //while (c && (*(WORD*)(c-2)!=sig))
        //{
        //  //-0x1000 as FindCallOrJmpAbs always uses an offset of 0x1000
        //  c = Util::FindCallOrJmpAbs((DWORD)IsDBCSLeadByte,processStopAddress-c-0x1000+4,c-0x1000+4,false);
        //}
        if (!addr) {
            ConsoleOutput("vnreng:EME: pattern does not exist");
            return false;
        }
        HookParam hp = {};
        hp.address = addr;
        hp.offset = -0x8;
        hp.length_offset = 1;
        hp.type = NO_CONTEXT | DATA_INDIRECT;
        ConsoleOutput("vnreng: INSERT EmonEngine");
        NewHook(hp, "EmonEngine");
        //ConsoleOutput("EmonEngine, hook will only work with text speed set to slow or normal!");
        //else ConsoleOutput("Unknown EmonEngine engine");
        return true;
    }
    static void SpecialRunrunEngine(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
    {
        //CC_UNUSED(split);
        DWORD eax = regof(eax, esp_base), // *(DWORD *)(esp_base - 0x8),
            edx = regof(edx, esp_base); // *(DWORD *)(esp_base - 0x10);
        DWORD addr = eax + edx; // eax + edx
        *data = *(WORD*)(addr);
        *len = 2;
    }
    bool InsertRREHook()
    {
        ULONG addr = MemDbg::findCallAddress((ULONG)::IsDBCSLeadByte, processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:RRE: function call does not exist");
            return false;
        }
        WORD sig = 0x51c3;
        HookParam hp = {};
        hp.address = addr;
        hp.length_offset = 1;
        hp.type = NO_CONTEXT | DATA_INDIRECT;
        if ((*(WORD*)(addr - 2) != sig)) {
            hp.text_fun = SpecialRunrunEngine;
            ConsoleOutput("vnreng: INSERT Runrun#1");
            NewHook(hp, "RunrunEngine Old");
        }
        else {
            hp.offset = -0x8;
            ConsoleOutput("vnreng: INSERT Runrun#2");
            NewHook(hp, "RunrunEngine");
        }
        return true;
        //ConsoleOutput("RunrunEngine, hook will only work with text speed set to slow or normal!");
        //else ConsoleOutput("Unknown RunrunEngine engine");
    }
    bool InsertMEDHook()
    {
        for (DWORD i = processStartAddress; i < processStopAddress - 4; i++)
            if (*(DWORD*)i == 0x8175) //cmp *, 8175
                for (DWORD j = i, k = i + 0x100; j < k; j++)
                    if (*(BYTE*)j == 0xe8) {
                        DWORD t = j + 5 + *(DWORD*)(j + 1);
                        if (t > processStartAddress && t < processStopAddress) {
                            HookParam hp = {};
                            hp.address = t;
                            hp.offset = -0x8;
                            hp.length_offset = 1;
                            hp.type = BIG_ENDIAN;
                            ConsoleOutput("vnreng: INSERT MED");
                            NewHook(hp, "MED");
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
    /** 7/31/2015
     *  Sample game オタカ� *  Hooked address: 0x4413b0
     *
     *  GDI functions are cached: TextOutA and GetTextExtentPoint32A
     *
     *  004413AB   90               NOP
     *  004413AC   90               NOP
     *  004413AD   90               NOP
     *  004413AE   90               NOP
     *  004413AF   90               NOP
     *  004413B0   6A FF            PUSH -0x1   ; jichi: text in arg1, but text painted character by character
     *  004413B2   68 D0714900      PUSH .004971D0
     *  004413B7   64:A1 00000000   MOV EAX,DWORD PTR FS:[0]
     *  004413BD   50               PUSH EAX
     *  004413BE   64:8925 00000000 MOV DWORD PTR FS:[0],ESP
     *  004413C5   83EC 4C          SUB ESP,0x4C
     *  004413C8   A1 C00B4B00      MOV EAX,DWORD PTR DS:[0x4B0BC0]
     *  004413CD   53               PUSH EBX
     *  004413CE   55               PUSH EBP
     *  004413CF   56               PUSH ESI
     *  004413D0   57               PUSH EDI
     *  004413D1   8BF1             MOV ESI,ECX
     *  004413D3   894424 48        MOV DWORD PTR SS:[ESP+0x48],EAX
     *  004413D7   894424 4C        MOV DWORD PTR SS:[ESP+0x4C],EAX
     *  004413DB   894424 58        MOV DWORD PTR SS:[ESP+0x58],EAX
     *  004413DF   8B4424 6C        MOV EAX,DWORD PTR SS:[ESP+0x6C]
     *  004413E3   33DB             XOR EBX,EBX
     *  004413E5   50               PUSH EAX
     *  004413E6   8D4C24 4C        LEA ECX,DWORD PTR SS:[ESP+0x4C]
     *  004413EA   895C24 68        MOV DWORD PTR SS:[ESP+0x68],EBX
     *  004413EE   E8 74520400      CALL .00486667
     *  004413F3   8B4C24 78        MOV ECX,DWORD PTR SS:[ESP+0x78]
     *  004413F7   51               PUSH ECX
     *  004413F8   8D4C24 50        LEA ECX,DWORD PTR SS:[ESP+0x50]
     *  004413FC   E8 66520400      CALL .00486667
     *  00441401   8B5424 7C        MOV EDX,DWORD PTR SS:[ESP+0x7C]
     *  00441405   8D4C24 58        LEA ECX,DWORD PTR SS:[ESP+0x58]
     *  00441409   52               PUSH EDX
     *  0044140A   E8 58520400      CALL .00486667
     *  0044140F   8B4424 70        MOV EAX,DWORD PTR SS:[ESP+0x70]
     *  00441413   894424 50        MOV DWORD PTR SS:[ESP+0x50],EAX
     *  00441417   8B4424 74        MOV EAX,DWORD PTR SS:[ESP+0x74]
     *  0044141B   83F8 FF          CMP EAX,-0x1
     *  0044141E   75 06            JNZ SHORT .00441426
     *  00441420   895C24 54        MOV DWORD PTR SS:[ESP+0x54],EBX
     *  00441424   EB 2E            JMP SHORT .00441454
     *  00441426   8BC8             MOV ECX,EAX
     *  00441428   33D2             XOR EDX,EDX
     *  0044142A   81E1 FF000000    AND ECX,0xFF
     *  00441430   8AD4             MOV DL,AH
     *  00441432   81C9 00FFFFFF    OR ECX,0xFFFFFF00
     *  00441438   81E2 FF000000    AND EDX,0xFF
     *  0044143E   C1E1 08          SHL ECX,0x8
     *  00441441   0BCA             OR ECX,EDX
     *  00441443   C1E8 10          SHR EAX,0x10
     *  00441446   C1E1 08          SHL ECX,0x8
     *  00441449   25 FF000000      AND EAX,0xFF
     *  0044144E   0BC8             OR ECX,EAX
     *  00441450   894C24 54        MOV DWORD PTR SS:[ESP+0x54],ECX
     *  00441454   8B4424 48        MOV EAX,DWORD PTR SS:[ESP+0x48]
     *  00441458   3958 F8          CMP DWORD PTR DS:[EAX-0x8],EBX
     *  0044145B   0F84 7A030000    JE .004417DB
     *  00441461   8B8E 08020000    MOV ECX,DWORD PTR DS:[ESI+0x208]
     *  00441467   83F9 20          CMP ECX,0x20
     *  0044146A   0F8D 35030000    JGE .004417A5
     *  00441470   0FBE00           MOVSX EAX,BYTE PTR DS:[EAX]
     *  00441473   83E8 09          SUB EAX,0x9
     *  00441476   0F84 29030000    JE .004417A5
     *  0044147C   48               DEC EAX
     *  0044147D   0F84 0A030000    JE .0044178D
     *  00441483   83E8 03          SUB EAX,0x3
     *  00441486   0F84 19030000    JE .004417A5
     *  0044148C   8BBE 38010000    MOV EDI,DWORD PTR DS:[ESI+0x138]
     *  00441492   68 80C84A00      PUSH .004AC880
     *  00441497   8BCF             MOV ECX,EDI
     *  00441499   E8 E2E9FDFF      CALL .0041FE80
     *  0044149E   3BC3             CMP EAX,EBX
     *  004414A0   7D 0F            JGE SHORT .004414B1
     *  004414A2   53               PUSH EBX
     *  004414A3   53               PUSH EBX
     *  004414A4   53               PUSH EBX
     *  004414A5   53               PUSH EBX
     *  004414A6   8D4C24 48        LEA ECX,DWORD PTR SS:[ESP+0x48]
     *  004414AA   E8 916DFDFF      CALL .00418240
     *  004414AF   EB 06            JMP SHORT .004414B7
     *  004414B1   8B4F 24          MOV ECX,DWORD PTR DS:[EDI+0x24]
     *  004414B4   8B0481           MOV EAX,DWORD PTR DS:[ECX+EAX*4]
     *  004414B7   8B48 04          MOV ECX,DWORD PTR DS:[EAX+0x4]
     *  004414BA   8B10             MOV EDX,DWORD PTR DS:[EAX]
     *  004414BC   894C24 24        MOV DWORD PTR SS:[ESP+0x24],ECX
     *  004414C0   895424 20        MOV DWORD PTR SS:[ESP+0x20],EDX
     *  004414C4   8B50 08          MOV EDX,DWORD PTR DS:[EAX+0x8]
     *  004414C7   8B40 0C          MOV EAX,DWORD PTR DS:[EAX+0xC]
     *  004414CA   8D4C24 10        LEA ECX,DWORD PTR SS:[ESP+0x10]
     *  004414CE   895424 28        MOV DWORD PTR SS:[ESP+0x28],EDX
     *  004414D2   51               PUSH ECX
     *  004414D3   8BCE             MOV ECX,ESI
     *  004414D5   894424 30        MOV DWORD PTR SS:[ESP+0x30],EAX
     *  004414D9   E8 52F3FFFF      CALL .00440830
     *  004414DE   8B5424 50        MOV EDX,DWORD PTR SS:[ESP+0x50]
     *  004414E2   33C9             XOR ECX,ECX
     *  004414E4   894C24 78        MOV DWORD PTR SS:[ESP+0x78],ECX
     *  004414E8   B8 B0B64900      MOV EAX,.0049B6B0
     *  004414ED   3B10             CMP EDX,DWORD PTR DS:[EAX]
     *  004414EF   7E 0B            JLE SHORT .004414FC
     *  004414F1   83C0 04          ADD EAX,0x4
     *  004414F4   41               INC ECX
     *  004414F5   3D C0B64900      CMP EAX,.0049B6C0
     *  004414FA  ^72 F1            JB SHORT .004414ED
     *  004414FC   8B5424 48        MOV EDX,DWORD PTR SS:[ESP+0x48]
     *  00441500   8D4424 18        LEA EAX,DWORD PTR SS:[ESP+0x18]
     *  00441504   894C24 78        MOV DWORD PTR SS:[ESP+0x78],ECX
     *  00441508   8B4C8E 3C        MOV ECX,DWORD PTR DS:[ESI+ECX*4+0x3C]
     *  0044150C   52               PUSH EDX
     *  0044150D   50               PUSH EAX
     *  0044150E   E8 3D34FCFF      CALL .00404950
     *  00441513   8B46 38          MOV EAX,DWORD PTR DS:[ESI+0x38]
     *  00441516   895C24 70        MOV DWORD PTR SS:[ESP+0x70],EBX
     *  0044151A   3BC3             CMP EAX,EBX
     *  0044151C   0F84 F9000000    JE .0044161B
     *  00441522   8B50 08          MOV EDX,DWORD PTR DS:[EAX+0x8]
     *  00441525   8B4E 78          MOV ECX,DWORD PTR DS:[ESI+0x78]
     *  00441528   3BCA             CMP ECX,EDX
     *  0044152A   0F8D EB000000    JGE .0044161B
     *  00441530   8B50 04          MOV EDX,DWORD PTR DS:[EAX+0x4]
     *  00441533   8B4424 10        MOV EAX,DWORD PTR SS:[ESP+0x10]
     *  00441537   8B7E 74          MOV EDI,DWORD PTR DS:[ESI+0x74]
     *  0044153A   8B2C8A           MOV EBP,DWORD PTR DS:[EDX+ECX*4]
     *  0044153D   8B4C24 18        MOV ECX,DWORD PTR SS:[ESP+0x18]
     *  00441541   897C24 7C        MOV DWORD PTR SS:[ESP+0x7C],EDI
     *  00441545   8B55 00          MOV EDX,DWORD PTR SS:[EBP]
     *  00441548   8D1C01           LEA EBX,DWORD PTR DS:[ECX+EAX]
     *  0044154B   8BCD             MOV ECX,EBP
     *  0044154D   FF52 08          CALL DWORD PTR DS:[EDX+0x8]
     *  00441550   3BF8             CMP EDI,EAX
     *  00441552   0F8D C3000000    JGE .0044161B
     *  00441558   EB 04            JMP SHORT .0044155E
     *  0044155A   8B7C24 7C        MOV EDI,DWORD PTR SS:[ESP+0x7C]
     *  0044155E   8B45 00          MOV EAX,DWORD PTR SS:[EBP]
     *  00441561   57               PUSH EDI
     *  00441562   8BCD             MOV ECX,EBP
     *  00441564   FF50 04          CALL DWORD PTR DS:[EAX+0x4]
     *  00441567   8BF8             MOV EDI,EAX
     *  00441569   8BCF             MOV ECX,EDI
     *  0044156B   8B17             MOV EDX,DWORD PTR DS:[EDI]
     *  0044156D   FF52 0C          CALL DWORD PTR DS:[EDX+0xC]
     *  00441570   85C0             TEST EAX,EAX
     *  00441572   0F84 A3000000    JE .0044161B
     *  00441578   8B07             MOV EAX,DWORD PTR DS:[EDI]
     *  0044157A   8D4C24 6C        LEA ECX,DWORD PTR SS:[ESP+0x6C]
     *  0044157E   51               PUSH ECX
     *  0044157F   8BCF             MOV ECX,EDI
     *  00441581   FF50 10          CALL DWORD PTR DS:[EAX+0x10]
     *  00441584   8B5424 6C        MOV EDX,DWORD PTR SS:[ESP+0x6C]
     *  00441588   8B4C24 78        MOV ECX,DWORD PTR SS:[ESP+0x78]
     *  0044158C   8D4424 30        LEA EAX,DWORD PTR SS:[ESP+0x30]
     *  00441590   52               PUSH EDX
     *  00441591   8B4C8E 3C        MOV ECX,DWORD PTR DS:[ESI+ECX*4+0x3C]
     *  00441595   50               PUSH EAX
     *  00441596   C64424 6C 01     MOV BYTE PTR SS:[ESP+0x6C],0x1
     *  0044159B   E8 B033FCFF      CALL .00404950
     *  004415A0   8B10             MOV EDX,DWORD PTR DS:[EAX]
     *  004415A2   8B86 E4030000    MOV EAX,DWORD PTR DS:[ESI+0x3E4]
     *  004415A8   03DA             ADD EBX,EDX
     *  004415AA   8B5424 6C        MOV EDX,DWORD PTR SS:[ESP+0x6C]
     *  004415AE   52               PUSH EDX
     *  004415AF   50               PUSH EAX
     *  004415B0   E8 BB020000      CALL .00441870
     *  004415B5   83C4 08          ADD ESP,0x8
     *  004415B8   85C0             TEST EAX,EAX
     *  004415BA   74 08            JE SHORT .004415C4
     *  004415BC   3B5C24 28        CMP EBX,DWORD PTR SS:[ESP+0x28]
     *  004415C0   7F 43            JG SHORT .00441605
     *  004415C2   EB 18            JMP SHORT .004415DC
     *  004415C4   8B4C24 6C        MOV ECX,DWORD PTR SS:[ESP+0x6C]
     *  004415C8   8B86 E0030000    MOV EAX,DWORD PTR DS:[ESI+0x3E0]
     *  004415CE   51               PUSH ECX
     *  004415CF   50               PUSH EAX
     *  004415D0   E8 9B020000      CALL .00441870
     *  004415D5   83C4 08          ADD ESP,0x8
     *  004415D8   85C0             TEST EAX,EAX
     *  004415DA   74 31            JE SHORT .0044160D
     *  004415DC   8D4C24 6C        LEA ECX,DWORD PTR SS:[ESP+0x6C]
     *  004415E0   C64424 64 00     MOV BYTE PTR SS:[ESP+0x64],0x0
     *  004415E5   E8 404F0400      CALL .0048652A
     *  004415EA   8B7C24 7C        MOV EDI,DWORD PTR SS:[ESP+0x7C]
     *  004415EE   8B55 00          MOV EDX,DWORD PTR SS:[EBP]
     *  004415F1   47               INC EDI
     *  004415F2   8BCD             MOV ECX,EBP
     *  004415F4   897C24 7C        MOV DWORD PTR SS:[ESP+0x7C],EDI
     *  004415F8   FF52 08          CALL DWORD PTR DS:[EDX+0x8]
     *  004415FB   3BF8             CMP EDI,EAX
     *  004415FD  ^0F8C 57FFFFFF    JL .0044155A
     *  00441603   EB 16            JMP SHORT .0044161B
     *  00441605   C74424 70 010000>MOV DWORD PTR SS:[ESP+0x70],0x1
     *  0044160D   8D4C24 6C        LEA ECX,DWORD PTR SS:[ESP+0x6C]
     *  00441611   C64424 64 00     MOV BYTE PTR SS:[ESP+0x64],0x0
     *  00441616   E8 0F4F0400      CALL .0048652A
     *  0044161B   8B4424 10        MOV EAX,DWORD PTR SS:[ESP+0x10]
     *  0044161F   8B4C24 18        MOV ECX,DWORD PTR SS:[ESP+0x18]
     *  00441623   03C8             ADD ECX,EAX
     *  00441625   8B4424 28        MOV EAX,DWORD PTR SS:[ESP+0x28]
     *  00441629   3BC8             CMP ECX,EAX
     *  0044162B   7E 18            JLE SHORT .00441645
     *  0044162D   8B5424 48        MOV EDX,DWORD PTR SS:[ESP+0x48]
     *  00441631   8B86 E0030000    MOV EAX,DWORD PTR DS:[ESI+0x3E0]
     *  00441637   52               PUSH EDX
     *  00441638   50               PUSH EAX
     *  00441639   E8 32020000      CALL .00441870
     *  0044163E   83C4 08          ADD ESP,0x8
     *  00441641   85C0             TEST EAX,EAX
     *  00441643   74 08            JE SHORT .0044164D
     *  00441645   8B4424 70        MOV EAX,DWORD PTR SS:[ESP+0x70]
     *  00441649   85C0             TEST EAX,EAX
     *  0044164B   74 3F            JE SHORT .0044168C
     *  0044164D   8B8E 08020000    MOV ECX,DWORD PTR DS:[ESI+0x208]
     *  00441653   41               INC ECX
     *  00441654   8BC1             MOV EAX,ECX
     *  00441656   898E 08020000    MOV DWORD PTR DS:[ESI+0x208],ECX
     *  0044165C   83F8 20          CMP EAX,0x20
     *  0044165F   0F8D 40010000    JGE .004417A5
     *  00441665   83EC 10          SUB ESP,0x10
     *  00441668   8B15 D0B04A00    MOV EDX,DWORD PTR DS:[0x4AB0D0]
     *  0044166E   8BDC             MOV EBX,ESP
     *  00441670   33C0             XOR EAX,EAX
     *  00441672   8B3D D4B04A00    MOV EDI,DWORD PTR DS:[0x4AB0D4]
     *  00441678   33C9             XOR ECX,ECX
     *  0044167A   8903             MOV DWORD PTR DS:[EBX],EAX
     *  0044167C   894B 04          MOV DWORD PTR DS:[EBX+0x4],ECX
     *  0044167F   8BCE             MOV ECX,ESI
     *  00441681   8953 08          MOV DWORD PTR DS:[EBX+0x8],EDX
     *  00441684   897B 0C          MOV DWORD PTR DS:[EBX+0xC],EDI
     *  00441687   E8 7418FCFF      CALL .00402F00
     *  0044168C   8B86 08020000    MOV EAX,DWORD PTR DS:[ESI+0x208]
     *  00441692   6A 00            PUSH 0x0
     *  00441694   8D0CC5 00000000  LEA ECX,DWORD PTR DS:[EAX*8]
     *  0044169B   2BC8             SUB ECX,EAX
     *  0044169D   8B948E 78040000  MOV EDX,DWORD PTR DS:[ESI+ECX*4+0x478]
     *  004416A4   8DAC8E 70040000  LEA EBP,DWORD PTR DS:[ESI+ECX*4+0x470]
     *  004416AB   52               PUSH EDX
     *  004416AC   8BCD             MOV ECX,EBP
     *  004416AE   E8 7D8A0000      CALL .0044A130
     *  004416B3   8BD8             MOV EBX,EAX
     *  004416B5   8D4424 48        LEA EAX,DWORD PTR SS:[ESP+0x48]
     *  004416B9   50               PUSH EAX
     *  004416BA   8D7B 08          LEA EDI,DWORD PTR DS:[EBX+0x8]
     *  004416BD   8BCF             MOV ECX,EDI
     *  004416BF   E8 534F0400      CALL .00486617
     *  004416C4   8D4C24 4C        LEA ECX,DWORD PTR SS:[ESP+0x4C]
     *  004416C8   51               PUSH ECX
     *  004416C9   8D4F 04          LEA ECX,DWORD PTR DS:[EDI+0x4]
     *  004416CC   E8 464F0400      CALL .00486617
     *  004416D1   8B5424 50        MOV EDX,DWORD PTR SS:[ESP+0x50]
     *  004416D5   8D4C24 58        LEA ECX,DWORD PTR SS:[ESP+0x58]
     *  004416D9   8957 08          MOV DWORD PTR DS:[EDI+0x8],EDX
     *  004416DC   8B4424 54        MOV EAX,DWORD PTR SS:[ESP+0x54]
     *  004416E0   51               PUSH ECX
     *  004416E1   8D4F 10          LEA ECX,DWORD PTR DS:[EDI+0x10]
     *  004416E4   8947 0C          MOV DWORD PTR DS:[EDI+0xC],EAX
     *  004416E7   E8 2B4F0400      CALL .00486617
     *  004416EC   8B45 08          MOV EAX,DWORD PTR SS:[EBP+0x8]
     *  004416EF   85C0             TEST EAX,EAX
     *  004416F1   74 04            JE SHORT .004416F7
     *  004416F3   8918             MOV DWORD PTR DS:[EAX],EBX
     *  004416F5   EB 03            JMP SHORT .004416FA
     *  004416F7   895D 04          MOV DWORD PTR SS:[EBP+0x4],EBX
     *  004416FA   83EC 10          SUB ESP,0x10
     *  004416FD   895D 08          MOV DWORD PTR SS:[EBP+0x8],EBX
     *  00441700   8B4424 20        MOV EAX,DWORD PTR SS:[ESP+0x20]
     *  00441704   8B5424 28        MOV EDX,DWORD PTR SS:[ESP+0x28]
     *  00441708   8B7C24 2C        MOV EDI,DWORD PTR SS:[ESP+0x2C]
     *  0044170C   8BDC             MOV EBX,ESP
     *  0044170E   8D4C02 02        LEA ECX,DWORD PTR DS:[EDX+EAX+0x2]
     *  00441712   8B5424 24        MOV EDX,DWORD PTR SS:[ESP+0x24]
     *  00441716   8903             MOV DWORD PTR DS:[EBX],EAX
     *  00441718   8D7C3A 02        LEA EDI,DWORD PTR DS:[EDX+EDI+0x2]
     *  0044171C   8953 04          MOV DWORD PTR DS:[EBX+0x4],EDX
     *  0044171F   894B 08          MOV DWORD PTR DS:[EBX+0x8],ECX
     *  00441722   8BCE             MOV ECX,ESI
     *  00441724   897B 0C          MOV DWORD PTR DS:[EBX+0xC],EDI
     *  00441727   E8 D417FCFF      CALL .00402F00
     *  0044172C   8B4424 4C        MOV EAX,DWORD PTR SS:[ESP+0x4C]
     *  00441730   8B48 F8          MOV ECX,DWORD PTR DS:[EAX-0x8]
     *  00441733   85C9             TEST ECX,ECX
     *  00441735   74 6E            JE SHORT .004417A5
     *  00441737   8B4E 3C          MOV ECX,DWORD PTR DS:[ESI+0x3C]
     *  0044173A   50               PUSH EAX
     *  0044173B   8D4424 24        LEA EAX,DWORD PTR SS:[ESP+0x24]
     *  0044173F   50               PUSH EAX
     *  00441740   E8 0B32FCFF      CALL .00404950
     *  00441745   8B5C24 20        MOV EBX,DWORD PTR SS:[ESP+0x20]
     *  00441749   8B4C24 18        MOV ECX,DWORD PTR SS:[ESP+0x18]
     *  0044174D   8B7C24 24        MOV EDI,DWORD PTR SS:[ESP+0x24]
     *  00441751   8BC3             MOV EAX,EBX
     *  00441753   2BC1             SUB EAX,ECX
     *  00441755   8BCF             MOV ECX,EDI
     *  00441757   99               CDQ
     *  00441758   2BC2             SUB EAX,EDX
     *  0044175A   8B5424 14        MOV EDX,DWORD PTR SS:[ESP+0x14]
     *  0044175E   F7D9             NEG ECX
     *  00441760   D1F8             SAR EAX,1
     *  00441762   03CA             ADD ECX,EDX
     *  00441764   8B5424 10        MOV EDX,DWORD PTR SS:[ESP+0x10]
     *  00441768   F7D8             NEG EAX
     *  0044176A   03C2             ADD EAX,EDX
     *  0044176C   83EC 10          SUB ESP,0x10
     *  0044176F   8D7C39 02        LEA EDI,DWORD PTR DS:[ECX+EDI+0x2]
     *  00441773   8D5418 02        LEA EDX,DWORD PTR DS:[EAX+EBX+0x2]
     *  00441777   8BDC             MOV EBX,ESP
     *  00441779   8903             MOV DWORD PTR DS:[EBX],EAX
     *  0044177B   894B 04          MOV DWORD PTR DS:[EBX+0x4],ECX
     *  0044177E   8BCE             MOV ECX,ESI
     *  00441780   8953 08          MOV DWORD PTR DS:[EBX+0x8],EDX
     *  00441783   897B 0C          MOV DWORD PTR DS:[EBX+0xC],EDI
     *  00441786   E8 7517FCFF      CALL .00402F00
     *  0044178B   EB 18            JMP SHORT .004417A5
     *  0044178D   8D41 29          LEA EAX,DWORD PTR DS:[ECX+0x29]
     *  00441790   8D14C5 00000000  LEA EDX,DWORD PTR DS:[EAX*8]
     *  00441797   2BD0             SUB EDX,EAX
     *  00441799   391C96           CMP DWORD PTR DS:[ESI+EDX*4],EBX
     *  0044179C   74 07            JE SHORT .004417A5
     *  0044179E   41               INC ECX
     *  0044179F   898E 08020000    MOV DWORD PTR DS:[ESI+0x208],ECX
     *  004417A5   8B86 E8020000    MOV EAX,DWORD PTR DS:[ESI+0x2E8]
     *  004417AB   33DB             XOR EBX,EBX
     *  004417AD   3BC3             CMP EAX,EBX
     *  004417AF   74 2A            JE SHORT .004417DB
     *  004417B1   399E C8030000    CMP DWORD PTR DS:[ESI+0x3C8],EBX
     *  004417B7   75 22            JNZ SHORT .004417DB
     *  004417B9   8B86 C4030000    MOV EAX,DWORD PTR DS:[ESI+0x3C4]
     *  004417BF   8BCE             MOV ECX,ESI
     *  004417C1   50               PUSH EAX
     *  004417C2   E8 89040000      CALL .00441C50
     *  004417C7   3B86 3C020000    CMP EAX,DWORD PTR DS:[ESI+0x23C]
     *  004417CD   74 06            JE SHORT .004417D5
     *  004417CF   8986 38020000    MOV DWORD PTR DS:[ESI+0x238],EAX
     *  004417D5   8986 3C020000    MOV DWORD PTR DS:[ESI+0x23C],EAX
     *  004417DB   399E 30020000    CMP DWORD PTR DS:[ESI+0x230],EBX
     *  004417E1   75 3C            JNZ SHORT .0044181F
     *  004417E3   8BCE             MOV ECX,ESI
     *  004417E5   E8 C6040000      CALL .00441CB0
     *  004417EA   85C0             TEST EAX,EAX
     *  004417EC   75 31            JNZ SHORT .0044181F
     *  004417EE   399E 18020000    CMP DWORD PTR DS:[ESI+0x218],EBX
     *  004417F4   74 29            JE SHORT .0044181F
     *  004417F6   83BE C4020000 64 CMP DWORD PTR DS:[ESI+0x2C4],0x64
     *  004417FD   74 20            JE SHORT .0044181F
     *  004417FF   8B86 08020000    MOV EAX,DWORD PTR DS:[ESI+0x208]
     *  00441805   83F8 20          CMP EAX,0x20
     *  00441808   7D 1D            JGE SHORT .00441827
     *  0044180A   83C0 29          ADD EAX,0x29
     *  0044180D   8D0CC5 00000000  LEA ECX,DWORD PTR DS:[EAX*8]
     *  00441814   2BC8             SUB ECX,EAX
     *  00441816   391C8E           CMP DWORD PTR DS:[ESI+ECX*4],EBX
     *  00441819   74 0C            JE SHORT .00441827
     *  0044181B   6A 01            PUSH 0x1
     *  0044181D   EB 01            JMP SHORT .00441820
     *  0044181F   53               PUSH EBX
     *  00441820   8BCE             MOV ECX,ESI
     *  00441822   E8 49C5FEFF      CALL .0042DD70
     *  00441827   8D4C24 58        LEA ECX,DWORD PTR SS:[ESP+0x58]
     *  0044182B   C74424 64 030000>MOV DWORD PTR SS:[ESP+0x64],0x3
     *  00441833   E8 F24C0400      CALL .0048652A
     *  00441838   8D4C24 4C        LEA ECX,DWORD PTR SS:[ESP+0x4C]
     *  0044183C   C64424 64 02     MOV BYTE PTR SS:[ESP+0x64],0x2
     *  00441841   E8 E44C0400      CALL .0048652A
     *  00441846   8D4C24 48        LEA ECX,DWORD PTR SS:[ESP+0x48]
     *  0044184A   C74424 64 FFFFFF>MOV DWORD PTR SS:[ESP+0x64],-0x1
     *  00441852   E8 D34C0400      CALL .0048652A
     *  00441857   8B4C24 5C        MOV ECX,DWORD PTR SS:[ESP+0x5C]
     *  0044185B   5F               POP EDI
     *  0044185C   5E               POP ESI
     *  0044185D   5D               POP EBP
     *  0044185E   64:890D 00000000 MOV DWORD PTR FS:[0],ECX
     *  00441865   5B               POP EBX
     *  00441866   83C4 58          ADD ESP,0x58
     *  00441869   C2 1400          RETN 0x14
     *  0044186C   90               NOP
     *  0044186D   90               NOP
     *  0044186E   90               NOP
     *  0044186F   90               NOP
     *
     *  Another sample game: 不条琸�界の探偵令嬢
     */
    bool InsertAbelHook()
    {
        // jichi: If this pattern failed again, try the following pattern instead:
        // 004413D3   894424 48        MOV DWORD PTR SS:[ESP+0x48],EAX
        // 004413D7   894424 4C        MOV DWORD PTR SS:[ESP+0x4C],EAX
        // 004413DB   894424 58        MOV DWORD PTR SS:[ESP+0x58],EAX

        const DWORD character[] = { 0xc981d48a, 0xffffff00 };
        if (DWORD j = SearchPattern(processStartAddress, processStopAddress - processStartAddress, character, sizeof(character))) {
            j += processStartAddress;
            for (DWORD i = j - 0x100; j > i; j--)
                if (*(WORD*)j == 0xff6a) {
                    HookParam hp = {};
                    hp.address = j;
                    hp.offset = 4; // text in arg1
                    hp.type = USING_STRING | NO_CONTEXT;
                    ConsoleOutput("vnreng: INSERT Abel");
                    //GROWL_DWORD(hp.address);
                    NewHook(hp, "Abel");
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
        DWORD k = *(DWORD*)frame;
        k = *(DWORD*)(k + 4);
        if (*(BYTE*)(k - 5) != 0xe8)
            k = *(DWORD*)(frame + 4);
        DWORD j = k + *(DWORD*)(k - 4);
        if (j > processStartAddress && j < processStopAddress) {
            HookParam hp = {};
            hp.address = j;
            hp.offset = -0x10;
            hp.length_offset = 1;
            hp.type = BIG_ENDIAN;
            ConsoleOutput("vnreng: INSERT DynamicLive");
            NewHook(hp, "Live");
            //RegisterEngineType(ENGINE_LIVE);
            return true;
        }
        ConsoleOutput("vnreng:DynamicLive: failed");
        return true; // jichi 12/25/2013: return true
    }
    //void InsertLiveHook()
    //{
    //  ConsoleOutput("Probably Live. Wait for text.");
    //  trigger_fun=InsertLiveDynamicHook;
    //  SwitchTrigger(true);
    //}
    bool InsertLiveHook()
    {
        const BYTE ins[] = { 0x64,0x89,0x20,0x8b,0x45,0x0c,0x50 };
        ULONG addr = MemDbg::findBytes(ins, sizeof(ins), processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:Live: pattern not found");
            return false;
        }
        HookParam hp = {};
        hp.address = addr;
        hp.offset = -0x10;
        hp.length_offset = 1;
        hp.type = BIG_ENDIAN;
        ConsoleOutput("vnreng: INSERT Live");
        NewHook(hp, "Live");
        //RegisterEngineType(ENGINE_LIVE);
        //else ConsoleOutput("Unknown Live engine");
        return true;
    }

    void InsertBrunsHook()
    {
        if (Util::CheckFile(L"libscr.dll")) {
            HookParam hp = {};
            hp.offset = 4;
            hp.length_offset = 1;
            hp.type = USING_UNICODE;
            //?push_back@?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAEXG@Z
            if (Util::CheckFile(L"msvcp90.dll"))
                hp.address = (DWORD)GetProcAddress(GetModuleHandleW(L"msvcp90.dll"), "?push_back@?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAEXG@Z");
            else if (Util::CheckFile(L"msvcp80.dll"))
                hp.address = (DWORD)GetProcAddress(GetModuleHandleW(L"msvcp80.dll"), "?push_back@?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAEXG@Z");
            else if (Util::CheckFile(L"msvcp100.dll")) // jichi 8/17/2013: MSVCRT 10.0 and 11.0
                hp.address = (DWORD)GetProcAddress(GetModuleHandleW(L"msvcp100.dll"), "?push_back@?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAEXG@Z");
            else if (Util::CheckFile(L"msvcp110.dll"))
                hp.address = (DWORD)GetProcAddress(GetModuleHandleW(L"msvcp110.dll"), "?push_back@?$basic_string@GU?$char_traits@G@std@@V?$allocator@G@2@@std@@QAEXG@Z");
            if (hp.address) {
                ConsoleOutput("vnreng: INSERT Brus#1");
                NewHook(hp, "Bruns");
            }
        }
        //else
        // jichi 12/21/2013: Keep both bruns hooks
        // The first one does not work for games like 「オーク・キングダマモン娘繁殖�豚人王～�anymore.
        {
            union {
                DWORD i;
                DWORD* id;
                WORD* iw;
                BYTE* ib;
            };
            DWORD k = processStopAddress - 4;
            for (i = processStartAddress + 0x1000; i < k; i++) {
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
                    if (t > processStartAddress && t < processStopAddress) {
                        i = t;
                        for (j = i + 0x80; i < j; i++) {
                            if (*ib != 0xe8)
                                continue;
                            i++;
                            t = i + 4 + *id;
                            if (t > processStartAddress && t < processStopAddress) {

                                HookParam hp = {};
                                hp.address = t;
                                hp.offset = 4;
                                hp.length_offset = 1;
                                hp.type = USING_UNICODE | DATA_INDIRECT;
                                ConsoleOutput("vnreng: INSERT Brus#2");
                                NewHook(hp, "Bruns2");
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
    * Artikash 8/1/2018: new QLIE hook. old one misses on https://vndb.org/v22308 and https://vndb.org/v19182
    * ExtTextOut hook misses characters because of font caching
    * Method to find H-code: trace call stack from ExtTextOut until missing characters from default hook are found
    * /HW-1C*0:-20@base address of pattern
    * characterizing pattern:
    kimimeza.exe+100D9C - 55                    - push ebp
    kimimeza.exe+100D9D - 8B EC                 - mov ebp,esp
    kimimeza.exe+100D9F - 83 C4 E4              - add esp,-1C { 228 }
    kimimeza.exe+100DA2 - 53                    - push ebx
    kimimeza.exe+100DA3 - 56                    - push esi
    kimimeza.exe+100DA4 - 57                    - push edi
    kimimeza.exe+100DA5 - 33 D2                 - xor edx,edx
    kimimeza.exe+100DA7 - 89 55 FC              - mov [ebp-04],edx
    */
        bool InsertQLIE3Hook()
        {
            const BYTE bytes[] =
            {
                0x55,
                0x8b, 0xec,
                0x83, 0xc4, 0xe4,
                0x53,
                0x56,
                0x57,
                0x33, 0xd2,
                0x89, 0x55, 0xfc
            };
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("Textractor:QLIE3: pattern not found");
                //ConsoleOutput("Not QLIE2");
                return false;
            }

            HookParam hp = {};
            hp.type = USING_UNICODE | DATA_INDIRECT | USING_SPLIT;
            hp.length_offset = 1;
            hp.offset = pusha_esi_off - 4;
            hp.split = pusha_edi_off - 4;
            hp.address = addr;

            ConsoleOutput("Textractor: INSERT QLIE3");
            NewHook(hp, "QLiE3");
            //ConsoleOutput("QLIE2");
            return true;
        }
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
            //enum { addr_offset = 0 }; // current instruction is the first one
            ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
            if (!addr) {
                ConsoleOutput("vnreng:QLIE2: pattern not found");
                //ConsoleOutput("Not QLIE2");
                return false;
            }

            HookParam hp = {};
            hp.type = DATA_INDIRECT | NO_CONTEXT; // 0x408
            hp.length_offset = 1;
            hp.offset = 0x14;
            hp.address = addr;

            ConsoleOutput("vnreng: INSERT QLIE2");
            NewHook(hp, "QLiE2");
            //ConsoleOutput("QLIE2");
            return true;
        }

        // jichi: 8/18/2013: Change return type to bool
        bool InsertQLIE1Hook()
        {
            for (DWORD i = processStartAddress + 0x1000; i < processStopAddress - 4; i++)
                if (*(DWORD*)i == 0x7ffe8347) { // inc edi, cmp esi,7f
                    DWORD t = 0;
                    for (DWORD j = i; j < i + 0x10; j++) {
                        if (*(DWORD*)j == 0xa0) { // cmp esi,a0
                            t = 1;
                            break;
                        }
                    }
                    if (t)
                        for (DWORD j = i; j > i - 0x100; j--)
                            if (*(DWORD*)j == 0x83ec8b55) { // push ebp, mov ebp,esp, sub esp,*
                                HookParam hp = {};
                                hp.address = j;
                                hp.offset = 0x18;
                                hp.split = -0x18;
                                hp.length_offset = 1;
                                hp.type = DATA_INDIRECT | USING_SPLIT;
                                ConsoleOutput("vnreng: INSERT QLIE1");
                                NewHook(hp, "QLiE");
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
    {
        return InsertQLIE1Hook() || InsertQLIE2Hook() || InsertQLIE3Hook();
    }

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
      This approach works fine with game later than つよきす２学�
      But the original つよき�is quite different. I handle this case separately.
    ********************************************************************************************/

    namespace { // unnamed Candy

    // jichi 8/23/2013: split into two different engines
    //if (_wcsicmp(processName, L"systemc.exe")==0)
    // Process name is "SystemC.exe"
        bool InsertCandyHook1()
        {
            for (DWORD i = processStartAddress + 0x1000; i < processStopAddress - 4; i++)
                if ((*(DWORD*)i & 0xffffff) == 0x24f980) // cmp cl,24
                    for (DWORD j = i, k = i - 0x100; j > k; j--)
                        if (*(DWORD*)j == 0xc0330a8a) { // mov cl,[edx]; xor eax,eax
                            HookParam hp = {};
                            hp.address = j;
                            hp.offset = -0x10;    // jichi: text in ecx
                            hp.type = USING_STRING;
                            ConsoleOutput("vnreng: INSERT SystemC#1");
                            NewHook(hp, "SystemC");
                            //RegisterEngineType(ENGINE_CANDY);
                            return true;
                        }
            ConsoleOutput("vnreng:CandyHook1: failed");
            return false;
        }

        // jichi 8/23/2013: Process name is NOT "SystemC.exe"
        bool InsertCandyHook2()
        {
            for (DWORD i = processStartAddress + 0x1000; i < processStopAddress - 4; i++)
                if (*(WORD*)i == 0x5b3c || // cmp al,0x5b
                    (*(DWORD*)i & 0xfff8fc) == 0x5bf880) // cmp reg,0x5B
                    for (DWORD j = i, k = i - 0x100; j > k; j--)
                        if ((*(DWORD*)j & 0xffff) == 0x8b55) { // push ebp, mov ebp,esp, sub esp,*
                            HookParam hp = {};
                            hp.address = j;
                            hp.offset = 4;    // jichi: text in arg1
                            hp.type = USING_STRING;
                            ConsoleOutput("vnreng: INSERT SystemC#2");
                            NewHook(hp, "SystemC");
                            //RegisterEngineType(ENGINE_CANDY);
                            return true;
                        }
            ConsoleOutput("vnreng:CandyHook2: failed");
            return false;
        }

        /** jichi 10/2/2013: CHECKPOINT
         *
         *  [5/31/2013] 恋もHもお勉強も、おまかせ�お姉ちも�部
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
         //  enum { addr_offset = 0 };
         //  ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
         //  ULONG reladdr = SearchPattern(processStartAddress, range, ins, sizeof(ins));
         //  reladdr = 0x104a48;
         //  GROWL_DWORD(processStartAddress);
         //  //GROWL_DWORD3(reladdr, processStartAddress, range);
         //  if (!reladdr)
         //    return false;
         //
         //  HookParam hp = {};
         //  hp.address = processStartAddress + reladdr + addr_offset;
         //  hp.offset = -8;
         //  hp.type = USING_STRING|NO_CONTEXT;
         //  NewHook(hp, "Candy");
         //  return true;
         //}

    } // unnamed Candy

    // jichi 10/2/2013: Add new candy hook
    bool InsertCandyHook()
    {
        PcHooks::hookOtherPcFunctions();
        //if (0 == _wcsicmp(processName, L"systemc.exe"))
        if (Util::CheckFile(L"SystemC.exe"))
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
     *  Sample game: イセカイ・ラヴァーズ�体験版
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
    static void SpecialHookApricoT(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
    {
        DWORD reg_esi = *(DWORD*)(esp_base - 0x20);
        DWORD base = *(DWORD*)(reg_esi + 0x24);
        DWORD index = *(DWORD*)(reg_esi + 0x3c);
        DWORD* script = (DWORD*)(base + index * 4);
        // jichi 2/14/2015
        // Change reg_esp to the return address
        //DWORD reg_esp = regof(esp, esp_base);
        //*split = reg_esp;
        //*split = regof(esp, esp_base);
        DWORD arg = argof(16, esp_base); // return address
        *split = arg > processStartAddress ? arg - processStartAddress : arg; // use relative split value
        //*split = argof(1, esp_base);
        if (script[0] == L'<') {
            DWORD* end;
            for (end = script; *end != L'>'; end++); // jichi 2/14/2015: i.e. = ::wcschr(script) or script
            switch (script[1]) {
            case L'N':
                if (script[2] == L'a' && script[3] == L'm' && script[4] == L'e') {
                    buffer_index = 0;
                    for (script += 5; script < end; script++)
                        if (*script > 0x20)
                            wc_buffer[buffer_index++] = *script & 0xFFFF;
                    *len = buffer_index << 1;
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
                                while (*script != L'\\') {
                                    wc_buffer[buffer_index++] = *script & 0xffff;
                                    script++;
                                }
                                while (*script++ != L'}');
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
        for (DWORD i = processStartAddress + 0x1000; i < processStopAddress - 4; i++)
            if ((*(DWORD*)i & 0xfff8fc) == 0x3cf880)  // cmp reg,0x3c
                for (DWORD j = i + 3, k = i + 0x100; j < k; j++)
                    if ((*(DWORD*)j & 0xffffff) == 0x4c2) { // retn 4
                        HookParam hp = {};
                        hp.address = j + 3;
                        hp.text_fun = SpecialHookApricoT;
                        hp.type = USING_STRING | NO_CONTEXT | USING_UNICODE;
                        ConsoleOutput("vnreng: INSERT ApricoT");
                        //GROWL_DWORD3(hp.address, processStartAddress, processStopAddress);
                        NewHook(hp, "ApRicoT");
                        //RegisterEngineType(ENGINE_APRICOT);
                        // jichi 2/14/2015: disable cached GDI functions
                        ConsoleOutput("vnreng:ApRicoT: disable GDI hooks");

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
        hp.address = (DWORD)::GetTextExtentPoint32A;
        hp.offset = 0x8; // arg2 lpString
        hp.split = -0x18; // jichi 8/12/2014: = -4 - pusha_esp_off
        hp.type = USING_STRING | USING_SPLIT;
        ConsoleOutput("vnreng: INSERT StuffScriptEngine");
        NewHook(hp, "StuffScriptEngine");
        //RegisterEngine(ENGINE_STUFFSCRIPT);
    }
    bool InsertTriangleHook()
    {
        for (DWORD i = processStartAddress; i < processStopAddress - 4; i++)
            if ((*(DWORD*)i & 0xffffff) == 0x75403c) // cmp al,0x40; jne
                for (DWORD j = i + 4 + *(BYTE*)(i + 3), k = j + 0x20; j < k; j++)
                    if (*(BYTE*)j == 0xe8) {
                        DWORD t = j + 5 + *(DWORD*)(j + 1);
                        if (t > processStartAddress && t < processStopAddress) {
                            HookParam hp = {};
                            hp.address = t;
                            hp.offset = 4;
                            hp.type = USING_STRING;
                            ConsoleOutput("vnreng: INSERT Triangle");
                            NewHook(hp, "Triangle");
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
        for (DWORD i = processStartAddress; i < processStopAddress - 4; i++)
            if (*(DWORD*)i == 0x6381) // cmp *,8163
                if (DWORD j = SafeFindEntryAligned(i, 0x100)) {
                    // Artikash 7/20/2019: I don't understand how or why this is possible, but I found a game that by default has copy on write memory for its .text section
                    VirtualProtect((void*)j, 1, PAGE_EXECUTE_READ, DUMMY);
                    HookParam hp = {};
                    hp.address = j;
                    hp.offset = 8;
                    hp.length_offset = 1;
                    ConsoleOutput("vnreng: INSERT Pensil");
                    NewHook(hp, "Pensil");
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
        NtAllocateVirtualMemory(GetCurrentProcess(), &buffer, 0,
            &info.AllocationSize.LowPart, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        NtReadFile(hFile, 0, 0, 0, &ios, buffer, info.EndOfFile.LowPart, 0, 0);
        CloseHandle(hFile);
        BYTE* b = (BYTE*)buffer;
        DWORD len = info.EndOfFile.LowPart & ~1;
        if (len == info.AllocationSize.LowPart)
            len -= 2;
        b[len] = 0;
        b[len + 1] = 0;
        bool ret = wcsstr((LPWSTR)buffer, L"PENSIL") || wcsstr((LPWSTR)buffer, L"Pensil");
        NtFreeVirtualMemory(GetCurrentProcess(), &buffer, &info.AllocationSize.LowPart, MEM_RELEASE);
        return ret;
    }
#endif // if 0
    namespace { // unnamed
        void SpecialHookDebonosuScenario(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            DWORD retn = *(DWORD*)esp_base;
            if (*(WORD*)retn == 0xc483) // add esp, $  old Debonosu game
                hp->offset = 4; // text in arg1
            else // new Debonosu game
                hp->offset = -0x8; // text in ecx instead
              //hp->type ^= EXTERN_HOOK;
            hp->text_fun = nullptr;
            *data = *(DWORD*)(esp_base + hp->offset);
            *len = ::strlen((char*)*data);
            *split = FIXED_SPLIT_VALUE;
        }
        bool InsertDebonosuScenarioHook()
        {
            DWORD addr = Util::FindImportEntry(processStartAddress, (DWORD)lstrcatA);
            if (!addr) {
                ConsoleOutput("vnreng:Debonosu: lstrcatA is not called");
                return false;
            }
            DWORD search = 0x15ff | (addr << 16); // jichi 10/20/2014: call dword ptr ds
            addr >>= 16;
            for (DWORD i = processStartAddress; i < processStopAddress - 4; i++)
                if (*(DWORD*)i == search &&
                    *(WORD*)(i + 4) == addr && // call dword ptr lstrcatA
                    *(BYTE*)(i - 5) == 0x68) { // push $
                    DWORD push = *(DWORD*)(i - 4);
                    for (DWORD j = i + 6, k = j + 0x10; j < k; j++)
                        if (*(BYTE*)j == 0xb8 &&
                            *(DWORD*)(j + 1) == push)
                            if (DWORD hook_addr = SafeFindEntryAligned(i, 0x200)) {
                                HookParam hp = {};
                                hp.address = hook_addr;
                                hp.text_fun = SpecialHookDebonosuScenario;
                                //hp.type = USING_STRING;
                                hp.type = USING_STRING | NO_CONTEXT | USING_SPLIT | FIXING_SPLIT; // there is only one thread
                                ConsoleOutput("vnreng: INSERT Debonosu");
                                NewHook(hp, "Debonosu");
                                return true;
                            }
                }

            ConsoleOutput("vnreng:Debonosu: failed");
            //ConsoleOutput("Unknown Debonosu engine.");
            return false;
        }
        void SpecialHookDebonosuName(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            DWORD text = regof(ecx, esp_base);
            if (!text)
                return;
            *data = text;
            *len = ::strlen((LPCSTR)text);
            *split = FIXED_SPLIT_VALUE << 1;
        }
        bool InsertDebonosuNameHook()
        {
            const BYTE bytes[] = {
                // 0032f659   32c0             xor al,al
                // 0032f65b   5b               pop ebx
                // 0032f65c   8be5             mov esp,ebp
                // 0032f65e   5d               pop ebp
                // 0032f65f   c3               retn
0x55,            // 0032f660   55               push ebp    ; jichi: name text in ecx, which could be zero though
0x8b,0xec,       // 0032f661   8bec             mov ebp,esp
0x81,0xec, XX4,  // 0032f663   81ec 2c080000    sub esp,0x82c
0x8b,0x45, 0x08, // 0032f669   8b45 08          mov eax,dword ptr ss:[ebp+0x8]
0x53,            // 0032f66c   53               push ebx
0x56,            // 0032f66d   56               push esi
0x8b,0xf1,       // 0032f66e   8bf1             mov esi,ecx
0x85,0xc0,       // 0032f670   85c0             test eax,eax
0x8d,0x4d, 0xf0, // 0032f672   8d4d f0          lea ecx,dword ptr ss:[ebp-0x10]
0x0f,0x45,0xc8,  // 0032f675   0f45c8           cmovne ecx,eax
0x57             // 0032f678   57               push edi
            };
            ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("vnreng:DebonosuName: pattern NOT FOUND");
                return false;
            }
            HookParam hp = {};
            hp.address = addr;
            hp.text_fun = SpecialHookDebonosuName;
            //hp.type = USING_STRING;
            hp.type = USING_STRING | NO_CONTEXT | USING_SPLIT; //|FIXING_SPLIT; // there is only one thread
            ConsoleOutput("vnreng: INSERT DebonosuName");
            NewHook(hp, "DebonosuName");
            return true;
        }

    } // unnamed namespace

    bool InsertDebonosuHook()
    {
        bool ok = InsertDebonosuScenarioHook();
        if (ok)
            InsertDebonosuNameHook();
        return ok;
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
     *  Sample hooked call in 悪魔娘�看板料理 Aoi5
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
     *  [f9S30e0u]　が、それ�人間相手�話�� */
    namespace { // unnamed
        void SpecialHookSystemAoi(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            *split = 0; // 8/3/2014 jichi: split is zero, so return address is used as split
            if (hp->type & USING_UNICODE) {
                LPCWSTR wcs = (LPWSTR)argof(1, esp_base); // jichi: text on the top of the stack
                size_t size = ::wcslen(wcs);
                for (DWORD i = 0; i < size; i++)
                    if (wcs[i] == L'>' || wcs[i] == L']') { // skip leading ] for scenario and > for name threads
                        i++;
                        if (wcs[i] == 0x3000) // \u3000
                            i++;
                        *data = (DWORD)(wcs + i);
                        size -= i;
                        *len = size * 2; // * 2 for wstring
                        return;
                    }
            }
            else {
                LPCSTR cs = (LPCSTR)argof(1, esp_base); // jichi: text on the top of the stack
                size_t size = ::strlen(cs);
                for (DWORD i = 0; i < size; i++)
                    if (cs[i] == '>' || cs[i] == ']') {
                        i++;
                        if ((unsigned char)cs[i] == 0x81 && cs[i + 1] == 0x40) // \u3000
                            i += 2;
                        *data = (DWORD)(cs + i);
                        size -= i;
                        *len = size;
                        return;
                    }
            }
        }

        int GetSystemAoiVersion() // return result is cached
        {
            static int ret = 0;
            if (!ret) {
                if (Util::CheckFile(L"Aoi4.dll"))
                    ret = 4;
                else if (Util::CheckFile(L"Aoi5.dll"))
                    ret = 5;
                else if (Util::CheckFile(L"Aoi6.dll")) // not exist yet, for future version
                    ret = 6;
                else if (Util::CheckFile(L"Aoi7.dll")) // not exist yet, for future version
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
            Util::GetCodeRange(processStartAddress, &low, &high);

            // jichi 2/15/2015: Traverse the stack to dynamically find the ancestor call from the main module
            const DWORD stop = (stack & 0xffff0000) + 0x10000; // range to traverse the stack
            for (DWORD i = stack; i < stop; i += 4) {
                DWORD k = *(DWORD*)i;
                if (k > low && k < high && // jichi: if the stack address falls into the code region of the main exe module
                    ((*(WORD*)(k - 6) == 0x15ff) || *(BYTE*)(k - 5) == 0xe8)) { // jichi 10/20/2014: call dword ptr ds

                    HookParam hp = {};
                    hp.offset = 0x4; // target text is on the top of the stack
                    hp.text_fun = SpecialHookSystemAoi; // need to remove garbage
                    hp.type = utf16 ? USING_UNICODE : USING_STRING;

                    i = *(DWORD*)(k - 4); // get function call address
                    if (*(DWORD*)(k - 5) == 0xe8) // short jump
                        hp.address = i + k;
                    else
                        hp.address = *(DWORD*)i; // jichi: long jump, this is what is happening in Aoi5
                      //NewHook(hp, "SofthouseChara");
                      //GROWL_DWORD(hp.address); // BUNNYBLACK: 0x10024730, base 0x01d0000
                    if (hp.address) {
                        ConsoleOutput("vnreng: INSERT SystemAoi");
                        if (addr == ::GetGlyphOutlineW)
                            NewHook(hp, "SystemAoi2"); // jichi 2/12/2015
                        else
                            NewHook(hp, "SystemAoi"); // jichi 7/8/2014: renamed, see: ja.wikipedia.org/wiki/ソフトハウスキャラ
                        ConsoleOutput("vnreng:SystemAoi: disable GDI hooks");

                    }
                    else
                        ConsoleOutput("vnreng: failed to detect SystemAoi");
                    //RegisterEngineType(ENGINE_SOFTHOUSE);
                    return true;
                }
            }
            ConsoleOutput("vnreng:SystemAoi: failed");
            return true; // jichi 12/25/2013: return true
        }

        bool InsertSystemAoiDynamic()
        {
            ConsoleOutput("vnreng: DYNAMIC SystemAoi");
            //ConsoleOutput("Probably SoftHouseChara. Wait for text.");
            trigger_fun = InsertSystemAoiDynamicHook;
            return true;
        }

        ULONG findAoiProc(HMODULE hModule, LPCSTR functionName, int minParamNum = 0, int maxParamNum = 10)
        {
            for (int i = minParamNum; i < maxParamNum; i++) {
                std::string sig; // function signature name, such as _AgsSpriteCreateText@20
                sig.push_back('_');
                sig += functionName;
                sig.push_back('@');
                sig += std::to_string(4ll * i);
                if (auto proc = ::GetProcAddress(hModule, sig.c_str()))
                    return (ULONG)proc;
            }
            return 0;
        }

        // jichi 7/26/2015: Backport logic in vnragent to vnrhook
        bool InsertSystemAoiStatic(HMODULE hModule, bool wideChar) // attach scenario
        {
            ULONG addr = findAoiProc(hModule, "AgsSpriteCreateText", 1);
            if (!addr) {
                ConsoleOutput("vnreng:SystemAoiStatic: function found");
                return false;
            }
            HookParam hp = {};
            hp.address = addr;
            hp.offset = 4 * 1; // arg1
            //hp.split = 4 * 2; // arg2
            hp.text_fun = SpecialHookSystemAoi;
            hp.type = wideChar ? USING_UNICODE : USING_STRING;
            //hp.type |= NO_CONTEXT|USING_SPLIT|SPLIT_INDIRECT;
            ConsoleOutput("vnreng: INSERT static SystemAoi");
            if (wideChar)
                NewHook(hp, "SystemAoiW");
            else
                NewHook(hp, "SystemAoiA");
            ConsoleOutput("vnreng:SystemAoiStatic: disable GDI hooks");

            return true;
        }
    } // unnamed namespace

    bool InsertSystemAoiHook() // this function always returns true
    {
        HMODULE hModule = ::GetModuleHandleA("Ags.dll");
        bool wideChar = true;
        if (hModule) // Aoi <= 3
            wideChar = false;
        else { // Aoi >= 4
            hModule = ::GetModuleHandleA("Ags5.dll");
            if (!hModule)
                hModule = ::GetModuleHandleA("Ags4.dll");
        }
        return hModule && InsertSystemAoiStatic(hModule, wideChar)
            || InsertSystemAoiDynamic();
    }

    static void SpecialHookCaramelBox(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
    {
        DWORD reg_ecx = *(DWORD*)(esp_base + hp->offset);
        BYTE* ptr = (BYTE*)reg_ecx;
        buffer_index = 0;
        while (ptr[0])
            if (ptr[0] == 0x28) { // Furigana format: (Kanji,Furi)
                ptr++;
                while (ptr[0] != 0x2c) //Copy Kanji
                    text_buffer[buffer_index++] = *ptr++;
                while (ptr[0] != 0x29) // Skip Furi
                    ptr++;
                ptr++;
            }
            else if (ptr[0] == 0x5c)
                ptr += 2;
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
        union { DWORD i; BYTE* pb; WORD* pw; DWORD* pd; };
        DWORD reg = -1;
        for (i = processStartAddress + 0x1000; i < processStopAddress - 4; i++) {
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
            }
            else if (*(pb - 3) == 3) { // add reg, [ebp+$disp_8]
                if (*(pb - 2) == (0x45 | (reg << 3)))
                    flag = 1;
            }
            else if (*(pb - 2) == 3) { // add reg, reg
                if (((*(pb - 1) >> 3) & 7) == reg)
                    flag = 1;
            }
            reg = -1;
            if (flag) {
                for (DWORD j = i, k = i - 0x100; j > k; j--) {
                    if ((*(DWORD*)j & 0xffff00ff) == 0x1000b8) { // mov eax,10??
                        HookParam hp = {};
                        hp.address = j & ~0xf;
                        hp.text_fun = SpecialHookCaramelBox;
                        hp.type = USING_STRING;
                        for (i &= ~0xffff; i < processStopAddress - 4; i++)
                            if (pb[0] == 0xe8) {
                                pb++;
                                if (pd[0] + i + 4 == hp.address) {
                                    pb += 4;
                                    if ((pd[0] & 0xffffff) == 0x04c483)
                                        hp.offset = 4;
                                    else hp.offset = -0xc;
                                    break;
                                }
                            }

                        if (hp.offset == 0) {
                            ConsoleOutput("vnreng:CaramelBox: failed, zero off");
                            return false;
                        }
                        ConsoleOutput("vnreng: INSERT CaramelBox");
                        NewHook(hp, "CaramelBox");
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
    namespace { // WolfRPG
    // jichi 10/13/2013: restored
        bool InsertOldWolfHook()
        {
            //__asm int 3   // debug
            // jichi 10/12/2013:
            // Step 1: find the address of GetTextMetricsA
            // Step 2: find where this function is called
            // Step 3: search "sub esp, XX" after where it is called
            enum { sub_esp = 0xec81 }; // jichi: caller pattern: sub esp = 0x81,0xec
            if (DWORD c1 = Util::FindCallAndEntryAbs((DWORD)GetTextMetricsA, processStopAddress - processStartAddress, processStartAddress, sub_esp))
                if (DWORD c2 = Util::FindCallOrJmpRel(c1, processStopAddress - processStartAddress, processStartAddress, 0)) {
                    union {
                        DWORD i;
                        WORD* k;
                    };
                    DWORD j;
                    for (i = c2 - 0x100, j = c2 - 0x400; i > j; i--)
                        if (*k == 0xec83) { // jichi 10/12/2013: 83 EC XX   sub esp, XX  See: http://lists.cs.uiuc.edu/pipermail/llvm-commits/Week-of-Mon-20120312.txt
                            HookParam hp = {};
                            hp.address = i;
                            hp.offset = -0xc;
                            hp.split = -0x18;
                            hp.type = DATA_INDIRECT | USING_SPLIT;
                            hp.length_offset = 1;
                            //GROWL_DWORD(hp.address); // jichi 6/5/2014: 淫乱勀��フィのRPG = 0x50a400
                            ConsoleOutput("vnreng: INSERT WolfRPG");
                            NewHook(hp, "WolfRPG");
                            return true;
                        }
                }

            //ConsoleOutput("Unknown WolfRPG engine.");
            ConsoleOutput("vnreng:WolfRPG: failed");
            return false;
        }

        // jichi 6/11/2015: See embed translation source code
        // Artikash 1/10/2019: RJ232953 hooked with HS-8*4@494480
        // CharNextA is called in the middle of target function, and at the start of it ecx points to struct with text at offset 4
        bool InsertWolf2Hook()
        {
            ULONG addr = MemDbg::findCallerAddressAfterInt3((ULONG)::CharNextA, processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("vnreng:WolfRPG2: failed to find target function");
                return false;
            }

            HookParam hp = {};
            hp.address = addr;
            hp.type = USING_STRING | DATA_INDIRECT;
            hp.offset = pusha_ecx_off - 4;
            hp.index = 4;
            ConsoleOutput("vnreng: INSERT WolfRPG2");
            NewHook(hp, "WolfRPG2");
            return true;
        }

    } // WolfRPG namespace

    bool InsertWolfHook()
    {
        return InsertOldWolfHook(), InsertWolf2Hook();
    }

    bool InsertIGSDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
    {
        if (addr != GetGlyphOutlineW)
            return false;
        DWORD i;
        i = *(DWORD*)frame;
        i = *(DWORD*)(i + 4);
        //if (SafeFillRange(L"mscorlib.ni.dll", &j, &k)) { // Artikash 6/30/2018: Dunno why addresses are needed
        while (*(BYTE*)i != 0xe8)
            i++;
        DWORD t = *(DWORD*)(i + 1) + i + 5;
        //if (t>j && t<k) {
        HookParam hp = {};
        hp.address = t;
        hp.offset = -0x10;
        hp.split = -0x18;
        hp.length_offset = 1;
        hp.type = USING_UNICODE | USING_SPLIT;
        ConsoleOutput("vnreng: INSERT IronGameSystem");
        NewHook(hp, "IronGameSystem");
        //ConsoleOutput("IGS - Please set text(ヂ�ス� display speed(表示速度) to fastest(瞬�");
        //RegisterEngineType(ENGINE_IGS);
        return true;
        //}
      //}
        ConsoleOutput("vnreng:IGS: failed");
        return true; // jichi 12/25/2013: return true
    }
    void InsertIronGameSystemHook()
    {
        //ConsoleOutput("Probably IronGameSystem. Wait for text.");
        trigger_fun = InsertIGSDynamicHook;
        ConsoleOutput("vnreng: TRIGGER IronGameSystem");
    }

    /********************************************************************************************
    AkabeiSoft2Try hook:
      Game folder contains YaneSDK.dll. Maybe we should call the engine Yane(屋� = roof)?
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

        typedef struct _NSTRING
        {
            PVOID vfTable;
            DWORD lenWithNull;
            DWORD lenWithoutNull;
            WCHAR str[1];
        } NSTRING;

        // qsort correctly identifies overflow.
        int cmp(const void* a, const void* b)
        {
            return *(int*)a - *(int*)b;
        }

        void SpecialHookAB2Try(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            //DWORD test = *(DWORD*)(esp_base - 0x10);
            DWORD edx = regof(edx, esp_base);
            if (edx != 0)
                return;

            //NSTRING *s = *(NSTRING **)(esp_base - 8);
            if (const NSTRING* s = (NSTRING*)regof(eax, esp_base)) {
                *len = s->lenWithoutNull << 1;
                *data = (DWORD)s->str;
                //*split = 0;
                *split = FIXED_SPLIT_VALUE; // 8/3/2014 jichi: change to single threads
            }
        }

        BOOL FindCharacteristInstruction()
        {
            const BYTE bytes[] = { 0x0F, 0xB7, 0x44, 0x50, 0x0C, 0x89 };
            for (auto addr : Util::SearchMemory(bytes, sizeof(bytes), PAGE_EXECUTE_READWRITE))
            {
                //GROWL_DWORD(addr);
                HookParam hp = {};
                hp.address = addr;
                hp.text_fun = SpecialHookAB2Try;
                hp.type = USING_STRING | NO_CONTEXT | USING_UNICODE;
                ConsoleOutput("vnreng: INSERT AB2Try");
                NewHook(hp, "AB2Try");
                //ConsoleOutput("Please adjust text speed to fastest/immediate.");
                //RegisterEngineType(ENGINE_AB2T);
                return TRUE;
            }
            return FALSE;
        }
    } // unnamed namespace
    bool InsertAB2TryHook()
    {
        bool ret = FindCharacteristInstruction();
        if (ret)
            ConsoleOutput("vnreng:AB2Try: found characteristic sequence");
        else
            ConsoleOutput("vnreng:AB2Try: cannot find characteristic sequence. Make sure you have start the game and have seen some text on the screen.");
        return ret;
    }

    /********************************************************************************************
    C4 hook: (Contributed by Stomp)
      Game folder contains C4.EXE or XEX.EXE.
    ********************************************************************************************/
    bool InsertC4Hook()
    {
        const BYTE bytes[] = { 0x8a, 0x10, 0x40, 0x80, 0xfa, 0x5f, 0x88, 0x15 };
        //enum { addr_offset = 0 };
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:C4: pattern not found");
            return false;
        }
        HookParam hp = {};
        hp.address = addr;
        hp.offset = -0x8;
        hp.type = DATA_INDIRECT | NO_CONTEXT;
        hp.length_offset = 1;
        ConsoleOutput("vnreng: INSERT C4");
        NewHook(hp, "C4");
        //RegisterEngineType(ENGINE_C4);
        return true;
    }

    /** 1/18/2015 jichi Add new WillPlus
     *  The old hook no longer works for new game.
     *  Sample game: [150129] [honeybee] RE:BIRTHDAY SONG
     *
     *  Note, WillPlus engine is migrating to UTF16 using GetGlyphOutlineW such as:
     *      [141218] [Guily] 手�めにされる九人の堕女
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

    namespace { // unnamed
#if 0
        static bool InsertWillPlusHook2() // jichi 1/18/2015: Add new hook
        {
            ULONG processStartAddress, processStopAddress;
            if (!FillRange(processName, &startAddress, &stopAddress)) { // need accurate stopAddress
                ConsoleOutput("vnreng:WillPlus2: failed to get memory range");
                return false;
            }

            // The following won't work after inserting WillPlus1, which also produces int3
            //ULONG addr = MemDbg::findCallerAddressAfterInt3((DWORD)::GetGlyphOutlineA, processStartAddress, processStopAddress);

            // 00418210   81ec b4000000    sub esp,0xb4
            enum { sub_esp = 0xec81 }; // jichi: caller pattern: sub esp = 0x81,0xec
            ULONG addr = MemDbg::findCallerAddress((ULONG)::GetGlyphOutlineA, sub_esp, processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("vnreng:WillPlus2: could not find caller of GetGlyphOutlineA");
                return false;
            }

            HookParam hp = {};
            hp.address = addr;
            hp.offset = 4 * 8; // arg8, address of text

            // Strategy 1: Use caller's address as split
            //hp.type = USING_STRING; // merge different scenario threads

            // Strategy 2: use arg1 as split
            hp.type = USING_STRING | NO_CONTEXT | USING_SPLIT; // merge different scenario threads
            hp.split = 4 * 1; // arg1 as split to get rid of saving message

            // Strategy 3: merge all threads
            //hp.type = USING_STRING|NO_CONTEXT|FIXING_SPLIT; // merge different scenario threads

            ConsoleOutput("vnreng: INSERT WillPlus2");
            NewHook(hp, "WillPlus2");
            return true;
        }
#endif // 0

        void SpecialHookWillPlus(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            //static DWORD detect_offset; // jichi 1/18/2015: this makes sure it only runs once
            //if (detect_offset)
            //  return;
            DWORD i, l;
            union {
                DWORD retn;
                WORD* pw;
                BYTE* pb;
            };
            retn = *(DWORD*)esp_base; // jichi 1/18/2015: dynamically find function return address
            i = 0;
            while (*pw != 0xc483) { // add esp, $
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
                hp->offset = *(pb + 2) - 8;

                // Still extract the first text
                //hp->type ^= EXTERN_HOOK;
                char* str = *(char**)(esp_base + hp->offset);
                *data = (DWORD)str;
                *len = ::strlen(str);
                *split = 0; // 8/3/2014 jichi: use return address as split

            }
            else { // jichi 1/19/2015: Try willplus2
                ConsoleOutput("vnreng: WillPlus1 pattern not found, try WillPlus2 instead");
                hp->offset = 4 * 8; // arg8, address of text
                hp->type = USING_STRING | NO_CONTEXT | USING_SPLIT; // merge different scenario threads
                hp->split = 4 * 1; // arg1 as split to get rid of saving message
                // The first text is skipped here
                //char *str = *(char **)(esp_base + hp->offset);
                //*data = (DWORD)str;
                //*len = ::strlen(str);
            }
            hp->text_fun = nullptr; // stop using text_fun any more
            //detect_offset = 1;
        }

        // Although the new hook also works for the old game, the old hook is still used by default for compatibility
        bool InsertOldWillPlusHook()
        {
            //__debugbreak();
            enum { sub_esp = 0xec81 }; // jichi: caller pattern: sub esp = 0x81,0xec byte
            ULONG addr = MemDbg::findCallerAddress((ULONG)::GetGlyphOutlineA, sub_esp, processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("vnreng:WillPlus: function call not found");
                return false;
            }

            HookParam hp = {};
            hp.address = addr;
            hp.text_fun = SpecialHookWillPlus;
            hp.type = USING_STRING;
            ConsoleOutput("vnreng: INSERT WillPlus");
            NewHook(hp, "WillPlus");
            //RegisterEngineType(ENGINE_WILLPLUS);
            return true;
        }

        const char* _willplus_trim_a(const char* text, size_t* size)
        {
            int textSize = ::strlen(text);
            int prefix = 0;
            if (text[0] == '%') {
                while (prefix < textSize - 1 && text[prefix] == '%' && ::isupper(text[prefix + 1])) {
                    prefix += 2;
                    while (::isupper(text[prefix]))
                        prefix++;
                }
            }
            {
                int pos = textSize;
                for (int i = textSize - 1; i >= prefix; i--) {
                    char ch = text[i];
                    if (::isupper(ch))
                        ;
                    else if (ch == '%')
                        pos = i;
                    else
                        break;
                }
                int suffix = textSize - pos;
                if (size)
                    *size = textSize - prefix - suffix;
            }
            return text + prefix;
        }

        const wchar_t* _willplus_trim_w(const wchar_t* text, size_t* size)
        {
            int textSize = ::wcslen(text);
            int prefix = 0;
            if (text[0] == '%') {
                while (prefix < textSize - 1 && text[prefix] == '%' && ::isupper(text[prefix + 1])) {
                    prefix += 2;
                    while (::isupper(text[prefix]))
                        prefix++;
                }
            }
            {
                int pos = textSize;
                for (int i = textSize - 1; i >= prefix; i--) {
                    wchar_t ch = text[i];
                    if (::isupper(ch))
                        ;
                    else if (ch == '%')
                        pos = i;
                    else
                        break;
                }
                int suffix = textSize - pos;
                if (size)
                    *size = textSize - prefix - suffix;
            }
            return text + prefix;
        }

        void SpecialHookWillPlusA(DWORD esp_base, HookParam*, BYTE index, DWORD* data, DWORD* split, DWORD* len)
        {
            auto text = (LPCSTR)regof(eax, esp_base);
            if (!text)
                return;
            if (index) // index == 1 is name
                text -= 1024;
            if (!*text)
                return;
            text = _willplus_trim_a(text, (size_t*)len);
            *data = (DWORD)text;
            *split = FIXED_SPLIT_VALUE << index;
        }

        bool InsertWillPlusAHook()
        {
            const BYTE bytes[] = {
              0x81,0xec, 0x14,0x08,0x00,0x00 // 0042B5E0   81EC 14080000    SUB ESP,0x814	; jichi: text in eax, name in eax - 1024, able to copy
            };
            DWORD addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
            if (!addr) {
                ConsoleOutput("vnreng:WillPlusA: pattern not found");
                return false;
            }
            HookParam hp = {};
            hp.address = addr;
            hp.text_fun = SpecialHookWillPlusA;
            hp.type = NO_CONTEXT;
            hp.filter_fun = NewLineStringFilter; // remove two characters of "\\n"
            ConsoleOutput("vnreng: INSERT WillPlusA");
            NewHook(hp, "WillPlusA");
            return true;
        }

        void SpecialHookWillPlusW(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            auto text = (LPCWSTR)regof(ecx, esp_base);
            if (!text || !*text)
                return;
            text = _willplus_trim_w(text, (size_t*)len);
            *len *= 2;
            *data = (DWORD)text;
            *split = FIXED_SPLIT_VALUE << hp->user_value;
        }

        bool InsertWillPlusWHook()
        {
            const BYTE bytes1[] = { // scenario
              0x83,0xc0, 0x20,     // 00452b02   83c0 20     add eax,0x20    ; jichi: hook before here, text in ecx
              0x33,0xd2,           // 00452b05   33d2        xor edx,edx
              0x8b,0xc1,           // 00452b07   8bc1        mov eax,ecx
              0xc7,0x84,0x24, 0xe0,0x01,0x00,0x00, 0x07,0x00,0x00,0x00  // 00452b09   c78424 e0010000 07000000      mov dword ptr ss:[esp+0x1e0],0x7
                                                                        // 00452b14   c78424 dc010000 00000000      mov dword ptr ss:[esp+0x1dc],0x0
            };
            const BYTE bytes2[] = { // name
              0x33,0xdb,   // 00453521   33db                            xor ebx,ebx  ; jichi: hook here, text in ecx
              0x33,0xd2,   // 00453523   33d2                            xor edx,edx
              0x8b,0xc1,   // 00453525   8bc1                            mov eax,ecx
              0xc7,0x84,0x24, 0x88,0x00,0x00,0x00, 0x07,0x00,0x00,0x00 // 00453527   c78424 88000000 07000000        mov dword ptr ss:[esp+0x88],0x7
                                                                       // 00453532   899c24 84000000                 mov dword ptr ss:[esp+0x84],ebx
            };
            const BYTE* bytes[] = { bytes1, bytes2 };
            const size_t sizes[] = { sizeof(bytes1), sizeof(bytes2) };
            for (int i = 0; i < 2; i++) {
                DWORD addr = MemDbg::findBytes(bytes[i], sizes[i], processStartAddress, processStopAddress);
                if (!addr) {
                    ConsoleOutput("vnreng:WillPlusW: pattern not found");
                    return false;
                }
                HookParam hp = {};
                hp.address = addr;
                hp.text_fun = SpecialHookWillPlusW;
                hp.type = NO_CONTEXT;
                hp.user_value = i;
                hp.filter_fun = NewLineWideStringFilter; // remove two characters of "\\n"
                ConsoleOutput("vnreng: INSERT WillPlusW");
                NewHook(hp, "WillPlusW");
            }
            return true;
        }
        /*
            Artikash 9/29/2018: Updated WillPlus hook
            Sample games: https://vndb.org/r54549 https://vndb.org/v22705
            Not too sure about the stability of this pattern, but it works for both of the above
            Hook code for first game: /HQ-8*0@43D620. This seems fairly stable: __thiscall calling convention and first member points to string
            Method to find hook code: trace call stack from GetGlyphOutlineW
            Disassembly from first game (damekoi). The first few instructions are actually a common function prologue: not enough to locate hook
            Hooking SysAllocString also seems to work, but has some garbage
            0043D61D - C2 0800               - ret 0008 { 8 }
            0043D620 - 55                    - push ebp
            0043D621 - 8B EC                 - mov ebp,esp
            0043D623 - 6A FF                 - push -01 { 255 }
            0043D625 - 68 6B6D5400           - push 00546D6B { [139] }
            0043D62A - 64 A1 00000000        - mov eax,fs:[00000000] { 0 }
            0043D630 - 50                    - push eax
            0043D631 - 81 EC 30010000        - sub esp,00000130 { 304 }
            0043D637 - A1 08E05800           - mov eax,[0058E008] { [6A9138CD] }
            0043D63C - 33 C5                 - xor eax,ebp
            0043D63E - 89 45 EC              - mov [ebp-14],eax
            0043D641 - 53                    - push ebx
            0043D642 - 56                    - push esi
            0043D643 - 57                    - push edi
            0043D644 - 50                    - push eax
            0043D645 - 8D 45 F4              - lea eax,[ebp-0C]
            0043D648 - 64 A3 00000000        - mov fs:[00000000],eax { 0 }
            0043D64E - 8B F9                 - mov edi,ecx
            0043D650 - 89 BD E8FEFFFF        - mov [ebp-00000118],edi
            0043D656 - 8B 45 08              - mov eax,[ebp+08]
            0043D659 - 8B 4D 14              - mov ecx,[ebp+14]
            0043D65C - F3 0F10 45 1C         - movss xmm0,[ebp+1C]
            0043D661 - 8B 5D 18              - mov ebx,[ebp+18]
            0043D664 - 89 85 10FFFFFF        - mov [ebp-000000F0],eax
            0043D66A - 8B 45 10              - mov eax,[ebp+10]
            0043D66D - 89 85 08FFFFFF        - mov [ebp-000000F8],eax
            0043D673 - 89 47 68              - mov [edi+68],eax
            0043D676 - 8B 45 20              - mov eax,[ebp+20]
            0043D679 - 51                    - push ecx
            ...
        */
        static bool InsertNewWillPlusHook()
        {
            bool found = false;
            const BYTE characteristicInstructions[] =
            {
                0xc2, 0x08, 0, // ret 0008; Seems to always be ret 8 before the hookable function. not sure why, not sure if stable.
                0x55, // push ebp; hook here
                0x8b, 0xec, // mov ebp,esp
                0x6a, 0xff, // push -01
                0x68, XX4, // push ?
                0x64, 0xa1, 0, 0, 0, 0, // mov eax,fs:[0]
                0x50, // push eax
                0x81, 0xec, XX4, // sub esp,?
                0xa1, XX4, // mov eax,[?]
                0x33, 0xc5, // xor eax,ebp
                //0x89, 0x45, 0xec // mov [ebp-14],eax; not sure if 0x14 is stable
            };
            for (auto addr : Util::SearchMemory(characteristicInstructions, sizeof(characteristicInstructions)))
            {
                //GROWL_DWORD(addr);
                HookParam hp = {};
                hp.address = addr + 3;
                hp.type = USING_STRING | USING_UNICODE | DATA_INDIRECT;
                hp.offset = pusha_ecx_off - 4;
                hp.index = 0;
                NewHook(hp, "WillPlus2");
                found = true;
            }
            /*
            stolen from https://github.com/lgztx96
            hook cmp esi,0x3000
            Sample games:
            https://vndb.org/r54549
            https://vndb.org/v22705
            https://vndb.org/v24852
            https://vndb.org/v25719
            https://vndb.org/v27227
            https://vndb.org/v27385
            */
            const BYTE pattern[] =
            {
                0x81,0xfe,0x00,0x30,0x00,0x00   //81FE 00300000  cmp esi,0x3000
            };
            for (auto addr : Util::SearchMemory(pattern, sizeof(pattern), PAGE_EXECUTE, processStartAddress, processStopAddress))
            {
                HookParam hp = {};
                hp.address = addr;
                hp.type = USING_UNICODE;
                hp.offset = pusha_esi_off - 4;
                hp.length_offset = 1;
                NewHook(hp, "WillPlus3");
                found = true;
            }
            if (!found) ConsoleOutput("Textractor: WillPlus: failed to find instructions");
            return found;
        }

    } // unnamed namespace

    bool InsertWillPlusHook()
    {
        bool ok = InsertOldWillPlusHook();
        ok = InsertWillPlusWHook() || InsertWillPlusAHook() || InsertNewWillPlusHook() || ok;
        if (!ok) PcHooks::hookOtherPcFunctions();
        return ok;
    }

    /** jichi 9/14/2013
     *  TanukiSoft (*.tac)
     *
     *  Seems to be broken for new games in 2012 such like となり�
     *
     *  微少女: /HSN4@004983E0
     *  This is the same hook as ITH
     *  - addr: 4817888 (0x4983e0)
     *  - text_fun: 0x0
     *  - off: 4
     *  - type: 1025 (0x401)
     *
     *  隣り�ぷ�さ� /HSN-8@200FE7:TONARINO.EXE
     *  - addr: 2101223 (0x200fe7)
     *  - module: 2343491905 (0x8baed941)
     *  - off: 4294967284 = 0xfffffff4 = -0xc
     *  - type: 1089 (0x441)
     */
    bool InsertTanukiHook()
    {
        ConsoleOutput("vnreng: trying TanukiSoft");
        for (DWORD i = processStartAddress; i < processStopAddress - 4; i++)
            if (*(DWORD*)i == 0x8140)
                if (DWORD j = SafeFindEntryAligned(i, 0x400)) { // jichi 9/14/2013: might crash the game without admin priv
                  //GROWL_DWORD2(i, j);
                    HookParam hp = {};
                    hp.address = j;
                    hp.offset = 4;
                    hp.type = USING_STRING | NO_CONTEXT;
                    ConsoleOutput("vnreng: INSERT TanukiSoft");
                    NewHook(hp, "TanukiSoft");
                    return true;
                }

        //ConsoleOutput("Unknown TanukiSoft engine.");
        ConsoleOutput("vnreng:TanukiSoft: failed");
        return false;
    }
    static void SpecialHookRyokucha(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
    {
        const DWORD* base = (const DWORD*)esp_base;
        for (DWORD i = 1; i < 5; i++) {
            DWORD j = base[i];
            if ((j >> 16) == 0 && (j >> 8)) {
                hp->offset = i << 2;
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
            mov eax, fs: [0]
            mov eax, [eax]
            mov eax, [eax] //Step up SEH chain for 2 nodes.
            mov ecx, [eax + 0xC]
            mov eax, [eax + 4]
            add ecx, [ecx - 4]
            mov insert_addr, ecx
            cmp eax, [ecx + 3]
            sete al
            mov flag, al
        }
        if (flag) {
            HookParam hp = {};
            hp.address = insert_addr;
            hp.length_offset = 1;
            hp.text_fun = SpecialHookRyokucha;
            hp.type = BIG_ENDIAN;
            ConsoleOutput("vnreng: INSERT StudioRyokucha");
            NewHook(hp, "StudioRyokucha");
            return true;
        }
        //else ConsoleOutput("Unknown Ryokucha engine.");
        ConsoleOutput("vnreng:StudioRyokucha: failed");
        return true;
    }
    void InsertRyokuchaHook()
    {
        //ConsoleOutput("Probably Ryokucha. Wait for text.");
        trigger_fun = InsertRyokuchaDynamicHook;
        ConsoleOutput("vnreng: TRIGGER Ryokucha");
    }

    /**
     *  jichi 5/11/2014: Hook to the beginning of a function
     *
     *  Executable description shows "AVGEngineV2"
     *
     *  Cached wrong text can also be found in GetGlyphOutlineW.
     *
     *  4/27/2015 old logic:
     *  1. find the following location
     *     00A78144   66:833C70 00     CMP WORD PTR DS:[EAX+ESI*2],0x0
     *     i.e. 0x66833C7000
     *     There are several matches, the first one is used.
     *  2. find the first push operation after it
     *  3. find the function call after push, and hook to it
     *     The text is in the arg1, which is character by character
     *
     *  But in the new game since ウルスラグ� there the function call is not immediately after 0x66833C7000 any more.
     *  My own way to find the function to hook is as follows:
     *  1. find the following location
     *     00A78144   66:833C70 00     CMP WORD PTR DS:[EAX+ESI*2],0x0
     *     i.e. 0x66833C7000
     *     There are several matches, the first one is used.
     *  2. Use Ollydbg to debug step by step until the first function call is encountered
     *     Then, the text character is directly on the stack
     *
     *  Here's an example of Demonion II (reladdr = 0x18c540):
     *  The text is displayed character by character.
     *  sub_58C540 proc near
     *  arg_0 = dword ptr  8 // LPCSTR with 1 character
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
     *
     *  4/26/2015  ウルスラグ� *  base = 0xa30000, old hook addr = 0xbe6360
     *
     *  00A7813A   EB 02            JMP SHORT .00A7813E
     *  00A7813C   8BC7             MOV EAX,EDI
     *  00A7813E   8BB3 E4020000    MOV ESI,DWORD PTR DS:[EBX+0x2E4]
     *  00A78144   66:833C70 00     CMP WORD PTR DS:[EAX+ESI*2],0x0  ; jich: here's the first found segment
     *  00A78149   74 36            JE SHORT .00A78181
     *  00A7814B   837F 14 08       CMP DWORD PTR DS:[EDI+0x14],0x8
     *  00A7814F   72 08            JB SHORT .00A78159
     *  00A78151   8B07             MOV EAX,DWORD PTR DS:[EDI]
     *
     *  00A7883A   24 3C            AND AL,0x3C
     *  00A7883C   50               PUSH EAX
     *  00A7883D   C74424 4C 000000>MOV DWORD PTR SS:[ESP+0x4C],0x0
     *  00A78845   0F5B             ???                                      ; Unknown command
     *  00A78847   C9               LEAVE
     *  00A78848   F3:0F114424 44   MOVSS DWORD PTR SS:[ESP+0x44],XMM0
     *  00A7884E   F3:0F114C24 48   MOVSS DWORD PTR SS:[ESP+0x48],XMM1
     *  00A78854   E8 37040000      CALL .00A78C90  ; jichi: here's the target function to hook to, text char on the stack[0]
     *  00A78859   A1 888EDD00      MOV EAX,DWORD PTR DS:[0xDD8E88]
     *  00A7885E   A8 01            TEST AL,0x1
     *  00A78860   75 30            JNZ SHORT .00A78892
     *  00A78862   83C8 01          OR EAX,0x1
     *  00A78865   A3 888EDD00      MOV DWORD PTR DS:[0xDD8E88],EAX
     *
     *  Here's the new function call:
     *  00A78C8A   CC               INT3
     *  00A78C8B   CC               INT3
     *  00A78C8C   CC               INT3
     *  00A78C8D   CC               INT3
     *  00A78C8E   CC               INT3
     *  00A78C8F   CC               INT3
     *  00A78C90   55               PUSH EBP
     *  00A78C91   8BEC             MOV EBP,ESP
     *  00A78C93   56               PUSH ESI
     *  00A78C94   8BF1             MOV ESI,ECX
     *  00A78C96   57               PUSH EDI
     *  00A78C97   8B7D 08          MOV EDI,DWORD PTR SS:[EBP+0x8]
     *  00A78C9A   8B4E 04          MOV ECX,DWORD PTR DS:[ESI+0x4]
     *  00A78C9D   3BF9             CMP EDI,ECX
     *  00A78C9F   73 76            JNB SHORT .00A78D17
     *  00A78CA1   8B06             MOV EAX,DWORD PTR DS:[ESI]
     *  00A78CA3   3BC7             CMP EAX,EDI
     *  00A78CA5   77 70            JA SHORT .00A78D17
     *  00A78CA7   2BF8             SUB EDI,EAX
     *  00A78CA9   B8 93244992      MOV EAX,0x92492493
     *  00A78CAE   F7EF             IMUL EDI
     *  00A78CB0   03D7             ADD EDX,EDI
     *  00A78CB2   C1FA 04          SAR EDX,0x4
     *  00A78CB5   8BFA             MOV EDI,EDX
     *  00A78CB7   C1EF 1F          SHR EDI,0x1F
     *  00A78CBA   03FA             ADD EDI,EDX
     *  00A78CBC   3B4E 08          CMP ECX,DWORD PTR DS:[ESI+0x8]
     *  00A78CBF   75 09            JNZ SHORT .00A78CCA
     *  00A78CC1   6A 01            PUSH 0x1
     *  00A78CC3   8BCE             MOV ECX,ESI
     *  00A78CC5   E8 36030000      CALL .00A79000
     *  00A78CCA   8B56 04          MOV EDX,DWORD PTR DS:[ESI+0x4]
     *  00A78CCD   8D0CFD 00000000  LEA ECX,DWORD PTR DS:[EDI*8]
     *  00A78CD4   2BCF             SUB ECX,EDI
     *  00A78CD6   8B3E             MOV EDI,DWORD PTR DS:[ESI]
     *  00A78CD8   85D2             TEST EDX,EDX
     *  00A78CDA   74 7B            JE SHORT .00A78D57
     *  00A78CDC   66:8B048F        MOV AX,WORD PTR DS:[EDI+ECX*4]
     *  00A78CE0   66:8902          MOV WORD PTR DS:[EDX],AX
     *  00A78CE3   8B448F 04        MOV EAX,DWORD PTR DS:[EDI+ECX*4+0x4]
     *  00A78CE7   8942 04          MOV DWORD PTR DS:[EDX+0x4],EAX
     *  00A78CEA   8B448F 08        MOV EAX,DWORD PTR DS:[EDI+ECX*4+0x8]
     *  00A78CEE   8942 08          MOV DWORD PTR DS:[EDX+0x8],EAX
     *  00A78CF1   8B448F 0C        MOV EAX,DWORD PTR DS:[EDI+ECX*4+0xC]
     *  00A78CF5   8942 0C          MOV DWORD PTR DS:[EDX+0xC],EAX
     *  00A78CF8   C742 10 00000000 MOV DWORD PTR DS:[EDX+0x10],0x0
     *  00A78CFF   8B448F 14        MOV EAX,DWORD PTR DS:[EDI+ECX*4+0x14]
     *  00A78D03   8942 14          MOV DWORD PTR DS:[EDX+0x14],EAX
     *  00A78D06   8A448F 18        MOV AL,BYTE PTR DS:[EDI+ECX*4+0x18]
     *  00A78D0A   8842 18          MOV BYTE PTR DS:[EDX+0x18],AL
     *  00A78D0D   8346 04 1C       ADD DWORD PTR DS:[ESI+0x4],0x1C
     *  00A78D11   5F               POP EDI
     *  00A78D12   5E               POP ESI
     *  00A78D13   5D               POP EBP
     *  00A78D14   C2 0400          RETN 0x4
     *  00A78D17   3B4E 08          CMP ECX,DWORD PTR DS:[ESI+0x8]
     *  00A78D1A   75 09            JNZ SHORT .00A78D25
     *  00A78D1C   6A 01            PUSH 0x1
     *  00A78D1E   8BCE             MOV ECX,ESI
     *  00A78D20   E8 DB020000      CALL .00A79000
     *  00A78D25   8B4E 04          MOV ECX,DWORD PTR DS:[ESI+0x4]
     *  00A78D28   85C9             TEST ECX,ECX
     *  00A78D2A   74 2B            JE SHORT .00A78D57
     *  00A78D2C   66:8B07          MOV AX,WORD PTR DS:[EDI]
     *  00A78D2F   66:8901          MOV WORD PTR DS:[ECX],AX
     *  00A78D32   8B47 04          MOV EAX,DWORD PTR DS:[EDI+0x4]
     *  00A78D35   8941 04          MOV DWORD PTR DS:[ECX+0x4],EAX
     *  00A78D38   8B47 08          MOV EAX,DWORD PTR DS:[EDI+0x8]
     *  00A78D3B   8941 08          MOV DWORD PTR DS:[ECX+0x8],EAX
     *  00A78D3E   8B47 0C          MOV EAX,DWORD PTR DS:[EDI+0xC]
     *  00A78D41   8941 0C          MOV DWORD PTR DS:[ECX+0xC],EAX
     *  00A78D44   C741 10 00000000 MOV DWORD PTR DS:[ECX+0x10],0x0
     *  00A78D4B   8B47 14          MOV EAX,DWORD PTR DS:[EDI+0x14]
     *  00A78D4E   8941 14          MOV DWORD PTR DS:[ECX+0x14],EAX
     *  00A78D51   8A47 18          MOV AL,BYTE PTR DS:[EDI+0x18]
     *  00A78D54   8841 18          MOV BYTE PTR DS:[ECX+0x18],AL
     *  00A78D57   8346 04 1C       ADD DWORD PTR DS:[ESI+0x4],0x1C
     *  00A78D5B   5F               POP EDI
     *  00A78D5C   5E               POP ESI
     *  00A78D5D   5D               POP EBP
     *  00A78D5E   C2 0400          RETN 0x4
     *  00A78D61   CC               INT3
     *  00A78D62   CC               INT3
     *  00A78D63   CC               INT3
     *  00A78D64   CC               INT3
     *  00A78D65   CC               INT3
     */
    static bool InsertGXP1Hook()
    {
        union {
            DWORD i;
            DWORD* id;
            BYTE* ib;
        };
        //__asm int 3
        for (i = processStartAddress + 0x1000; i < processStopAddress - 4; i++) {
            // jichi example:
            // 00A78144   66:833C70 00     CMP WORD PTR DS:[EAX+ESI*2],0x0

            //find cmp word ptr [esi*2+eax],0
            if (*id != 0x703c8366)
                continue;
            i += 4;
            if (*ib != 0)
                continue;
            i++;
            DWORD j = i + 0x200;
            j = j < (processStopAddress - 8) ? j : (processStopAddress - 8);

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
                    if (*ib == 0xe8) { // jichi: find first long call after the push operation
                        i++;
                        DWORD addr = *id + i + 4;
                        if (addr > processStartAddress && addr < processStopAddress) {
                            HookParam hp = {};
                            hp.address = addr;
                            //hp.type = USING_UNICODE|DATA_INDIRECT;
                            hp.type = USING_UNICODE | DATA_INDIRECT | NO_CONTEXT | FIXING_SPLIT; // jichi 4/25/2015: Fixing split
                            hp.length_offset = 1;
                            hp.offset = 4;

                            //GROWL_DWORD3(hp.address, processStartAddress, hp.address - processStartAddress);

                            //DWORD call = Util::FindCallAndEntryAbs(hp.address, processStopAddress - processStartAddress, processStartAddress, 0xec81); // zero
                            //DWORD call = Util::FindCallAndEntryAbs(hp.address, processStopAddress - processStartAddress, processStartAddress, 0xec83); // zero
                            //DWORD call = Util::FindCallAndEntryAbs(hp.address, processStopAddress - processStartAddress, processStartAddress, 0xec8b55); // zero
                            //GROWL_DWORD3(call, processStartAddress, call - processStartAddress);

                            ConsoleOutput("vnreng: INSERT GXP");
                            NewHook(hp, "GXP");

                            // jichi 5/13/2015: Disable hooking to GetGlyphOutlineW
                            // FIXME: GetGlyphOutlineW can extract name, but GXP cannot
                            ConsoleOutput("vnreng:GXP: disable GDI hooks");

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

    static bool InsertGXP2Hook()
    {
        // pattern = 0x0f5bc9f30f11442444f30f114c2448e8
        const BYTE bytes[] = {
           0x0f,0x5b,                      // 00A78845   0F5B             ???                                      ; Unknown command
           0xc9,                           // 00A78847   C9               LEAVE
           0xf3,0x0f,0x11,0x44,0x24, 0x44, // 00A78848   F3:0F114424 44   MOVSS DWORD PTR SS:[ESP+0x44],XMM0
           0xf3,0x0f,0x11,0x4c,0x24, 0x48, // 00A7884E   F3:0F114C24 48   MOVSS DWORD PTR SS:[ESP+0x48],XMM1
           0xe8 //37040000                 // 00A78854   E8 37040000      CALL .00A78C90  ; jichi: here's the target function to hook to, text char on the stack[0]
        };
        enum { addr_offset = sizeof(bytes) - 1 }; // 0x00a78854 - 0x00a78845
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:GXP2: pattern not found");
            return false;
        }

        HookParam hp = {};
        hp.address = addr + addr_offset;
        hp.type = USING_UNICODE | NO_CONTEXT | DATA_INDIRECT | FIXING_SPLIT;
        hp.length_offset = 1;
        ConsoleOutput("vnreng: INSERT GXP2");
        NewHook(hp, "GXP2");
        ConsoleOutput("vnreng:GXP: disable GDI hooks");

        return true;
    }

    bool InsertGXPHook()
    {
        // GXP1 and GXP2 are harmless to each other
        bool ok = InsertGXP1Hook();
        ok = InsertGXP2Hook() || ok;
        return ok;
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

        void SpecialHookAnex86(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
        {
            __asm
            {
                mov eax, esp_base
                mov ecx, [eax - 0xC]
                cmp byte ptr[ecx + 0xE], 0
                jnz _fin
                movzx ebx, byte ptr[ecx + 0xC]; Low byte
                movzx edx, byte ptr[ecx + 0xD]; High byte
                test edx, edx
                jnz _jis_char
                mov eax, data
                mov[eax], ebx
                mov eax, len
                mov[eax], 1
                jmp _fin
                _jis_char :
                cmp ebx, 0x7E
                    ja _fin
                    cmp edx, 0x7E
                    ja _fin
                    test dl, 1
                    lea eax, [ebx + 0x7E]
                    movzx ecx, byte ptr[JIS_tableL + ebx]
                    cmovnz eax, ecx
                    mov ah, byte ptr[JIS_tableH + edx]
                    ror ax, 8
                    mov ecx, data
                    mov[ecx], eax
                    mov ecx, len
                    mov[ecx], 2
                    _fin:
            }

        }
    } // unnamed namespace
    bool InsertAnex86Hook()
    {
        const BYTE bytes[] = {
            0x8a, XX, 0x0c, // mov ??,[ecx+0C]
            0x8a, XX, 0x0d  // mov ??,[ecx+0D]
        };
        bool found = false;
        for (auto addr : Util::SearchMemory(bytes, sizeof(bytes), PAGE_EXECUTE, processStartAddress, processStopAddress)) {
            //const DWORD dwords[] = {0x618ac033,0x0d418a0c}; // jichi 12/25/2013: Remove static keyword
            //for (DWORD i = processStartAddress + 0x1000; i < processStopAddress - 8; i++)
              //if (*(DWORD *)i == dwords[0])
                //if (*(DWORD *)(i + 4) == dwords[1]) {
            HookParam hp = {};
            if (*(BYTE*)(addr - 2) == 0x33 || *(BYTE*)(addr - 2) == 0x31) addr = addr - 2;
            hp.address = addr;
            hp.offset = pusha_ecx_off - 4;
            hp.text_fun = SpecialHookAnex86;
            //hp.type = EXTERN_HOOK;
            hp.length_offset = 1;
            ConsoleOutput("vnreng: INSERT Anex86");
            NewHook(hp, "Anex86");
            found = true;
        }
        if (found) return true;
        ConsoleOutput("vnreng:Anex86: failed");
        return false;
    }

    /**
     *  jichi 9/5/2013: NEXTON games with aInfo.db
     *  Sample games:
     *  - /HA-C@4D69E:InnocentBullet.exe (イノセントバレッ�)
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
#if 0
        // 0x8944241885c00f84
        const BYTE bytes[] = {
            //0xe8 //??,??,??,??,      00804147   e8 24d90100      call imoutoba.00821a70
            0x89,0x44,0x24, 0x18,   // 0080414c   894424 18        mov dword ptr ss:[esp+0x18],eax; hook here
            0x85,0xc0,              // 00804150   85c0             test eax,eax
            0x0f,0x84               // 00804152  ^0f84 c0feffff    je imoutoba.00804018
        };
        //enum { addr_offset = 0 };
        ULONG addr = processStartAddress; //- sizeof(bytes);
        do {
            addr += sizeof(bytes); // ++ so that each time return diff address
            ULONG range = min(processStopAddress - addr, MAX_REL_ADDR);
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
        } while (0xe8c38b57 != *(DWORD*)(addr - 8));
#endif // 0
        const BYTE bytes[] = {
          0x57,                   // 0044d696   57               push edi
          0x8b,0xc3,              // 0044d697   8bc3             mov eax,ebx
          0xe8, XX4,              // 0044d699   e8 6249fdff      call .00422000
          0x89,0x44,0x24, 0x18,   // 0044d69e   894424 18        mov dword ptr ss:[esp+0x18],eax ; jichi: this is the ith hook point
          0x85,0xc0,              // 0044d6a2   85c0             test eax,eax
          0x0f,0x84 //c2feffff    // 0044d6a4  ^0f84 c2feffff    je .0044d56c
        };
        enum { addr_offset = 0x0044d69e - 0x0044d696 }; // = 8
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
        if (!addr) {
            ConsoleOutput("vnreng:NEXTON: pattern not exist");
            return false;
        }

        //addr = MemDbg::findEnclosingAlignedFunction(addr); // range is around 50, use 80
        //if (!addr) {
        //  ConsoleOutput("vnreng:NEXTON: enclosing function not found");
        //  return false;
        //}

        //GROWL_DWORD3(processStartAddress, addr, *(DWORD *)(addr-8));
        //HookParam hp = {};
        //hp.address = addr;
        //hp.offset = 4; // text in arg1
        //hp.split = 4;

        HookParam hp = {};
        hp.address = addr + addr_offset;
        hp.length_offset = 1;
        //hp.offset = -0x10;
        //hp.type = BIG_ENDIAN; // 4

        // 魔王のくせに生イキ�っ �今度は性戦ぽ  // CheatEngine search for byte array: 8944241885C00F84
        //addr = 0x4583de; // wrong
        //addr = 0x5460ba;
        //addr = 0x5f3d8a;
        //addr = 0x768776;
        //addr = 0x7a5319;

        hp.offset = -0x24;
        hp.split = 4;
        hp.type = BIG_ENDIAN | USING_SPLIT; // 0x54

        // Indirect is needed for new games,
        // Such as: /HA-C*0@4583DE for 「魔王のくせに生イキ�っ���  //hp.type = BIG_ENDIAN|DATA_INDIRECT; // 12
        //hp.type = USING_UNICODE;
        //GROWL_DWORD3(addr, -hp.offset, hp.type);

        ConsoleOutput("vnreng: INSERT NEXTON");
        NewHook(hp, "NEXTON");

        //ConsoleOutput("vnreng:NEXTON: disable GDI hooks"); // There are no GDI functions hooked though
        // // disable GetGlyphOutlineA
        return true;
    }

    /** jichi 8/17/2014 Nexton1
     *  Sample games:
     *  - [Nomad][071026] 淫烙�巫女 Trial
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
        enum { addr_offset = 0 }; // distance to the beginning of the function
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);
        //GROWL_DWORD(addr); // supposed to be 0x4010e0
        if (!addr) {
            ConsoleOutput("vnreng:NEXTON1: pattern not found");
            return false;
        }
        //GROWL_DWORD(addr);

        HookParam hp = {};
        hp.address = addr + addr_offset;
        //hp.length_offset = 1;
        hp.offset = 4; // [esp+4] == arg0
        hp.type = USING_STRING;
        ConsoleOutput("vnreng: INSERT NEXTON1");
        NewHook(hp, "NEXTON1");
        return true;
    }

    /**
    *  Artikash 7/15/2018: Insert Tyranobuilder hook
    *  Sample game: https://vndb.org/v22252: /HWN-8:-1C@233A54:yuika_t.exe
    *  Artikash 9/11/2018: This is more than just Tyranobuilder. It's actually a hook for the V8 JavaScript runtime
    *  Sample game: https://www.freem.ne.jp/win/game/9672: /HQ8@2317A0:Prison.exe This new hook seems more reliable
    *  Nevermind both of those, just hook v8::String::Write https://v8docs.nodesource.com/node-0.8/d2/db3/classv8_1_1_string.html
    *  v8::String::Write - 55                    - push ebp
    *  v8::String::Write+1- 8B EC                 - mov ebp,esp
    *  v8::String::Write+3- 8B 45 14              - mov eax,[ebp+14]
    *  v8::String::Write+6- 8B 55 10              - mov edx,[ebp+10]
    *  v8::String::Write+9- 50                    - push eax
    *  v8::String::Write+A- 8B 45 0C              - mov eax,[ebp+0C]
    *  v8::String::Write+D- 52                    - push edx
    *  v8::String::Write+E- 8B 55 08              - mov edx,[ebp+08]
    *  v8::String::Write+11- 50                   - push eax
    *  v8::String::Write+12- 52                   - push edx
    *  v8::String::Write+13- 51                   - push ecx
    *  v8::String::Write+14- E8 B7C7FFFF          - call 6EF630 ; actual writing happens in this function, hooking after is possible
    *  v8::String::Write+19- 83 C4 14             - add esp,14 { 20 }
    *  v8::String::Write+1C- 5D                   - pop ebp
    *  v8::String::Write+1D- C2 1000              - ret 0010 { 16 }
    */
    void SpecialHookV8String(DWORD dwDatabase, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
    {
        DWORD ecx = *data;
        DWORD strPtr = *(DWORD*)ecx;
        *data = strPtr + 0xb;
        *len = *(short*)(strPtr + 7);
        //if (*len < 12) *split = 1; // To ensure this is caught by cyclic repetition detection, split if there's 6+ wide chars
        //*split = *(DWORD*)((BYTE*)hp->split + dwDatabase);
    }

    bool InsertV8Hook(HMODULE module)
    {
        auto [minAddress, maxAddress] = Util::QueryModuleLimits(module);
        for (const auto& pattern : Array<const BYTE[3]>{ { 0x55, 0x8b, 0xec }, { 0x55, 0x89, 0xe5 } })
        {
            int matches = Util::SearchMemory(pattern, sizeof(pattern), PAGE_EXECUTE, minAddress, maxAddress).size(), requiredRecords = matches * 20;
            if (matches > 10'000 && requiredRecords > spDefault.maxRecords)
            {
                memcpy(spDefault.pattern, pattern, spDefault.length = sizeof(pattern));
                spDefault.maxRecords = requiredRecords;
            }
        }
        std::tie(spDefault.minAddress, spDefault.maxAddress) = std::tuple{ minAddress, maxAddress };
        ConsoleOutput("Textractor: JavaScript hook is known to be low quality: try searching for hooks if you don't like it");
        HookParam hp = {};
        hp.address = (DWORD)GetProcAddress(module, "?Write@String@v8@@QBEHPAGHHH@Z");
        hp.offset = pusha_ecx_off - 4;
        hp.type = USING_UNICODE | USING_STRING;
        hp.text_fun = SpecialHookV8String;
        NewHook(hp, "JavaScript");
        const BYTE bytes[] = {
            0x83, 0xc4, XX, // add esp,XX
            0x5d, // pop ebp
            0xc2 // ret
        };
        if (DWORD addr = MemDbg::findBytes(bytes, sizeof(bytes), hp.address, hp.address + 0x30))
        {
            hp.address = addr;
            hp.offset = 0x8 + *(BYTE*)(addr + 2); // second argument + amount that the stack pointer is offset from arguments
            hp.type = USING_UNICODE | USING_STRING | NO_CONTEXT;
            hp.length_offset = (0x10 + *(BYTE*)(addr + 2)) / 4; // fourth argument + amount that the stack pointer is offset from arguments
            hp.text_fun = nullptr;
            NewHook(hp, "JavaScript2");
        }
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
    bool InsertUnicornHook()
    {
        // pattern: 2bce8bf8
        const BYTE bytes[] = {
          0x2b,0xce,  // sub ecx,esi ; hook here
          0x8b,0xf8   // mov edi,eax
        };
        //enum { addr_offset = 0 };
        ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
        if (!addr) {
            ConsoleOutput("vnreng:Unicorn: pattern not exist");
            return false;
        }

        HookParam hp = {};
        hp.type = NO_CONTEXT | DATA_INDIRECT;
        hp.length_offset = 1;
        hp.offset = -0x24; // jichi: text in edi
        hp.address = addr;

        //index = SearchPattern(processStartAddress, size,ins, sizeof(ins));
        //GROWL_DWORD2(base, index);

        ConsoleOutput("vnreng: INSERT Unicorn");
        NewHook(hp, "Unicorn");
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
     *  Example: ヂ�ウノイイ家�Trial /HBN-8*0:14@650A2F
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
     *    [130927]サ�ライホルモン
     *    [131025]ヂ�ウノイイ家�/HBN-8*0:14@650A2F (for trial version)
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
     *    くらむちめ�� *    まかろんソフト
     *    アイヂ�アファクトリー株式会社
     *    カラクリズ�
     *    合赼�社ファーストリー�
     *    有限会社ウルクスへブン
     *    有限会社ロータス
     *    株式会社CUCURI
     *    株式会社アバン
     *    株式会社インタラクヂ�ブブレインズ
     *    株式会社ウィンヂ�ール
     *    株式会社エヴァンジェ
     *    株式会社ポニーキャニオン
     *    株式会社大福エンターヂ�ンメン� */
    bool InsertArtemis1Hook()
    {
        const BYTE bytes[] = {
          0x83,0xc4, 0x0c, // add esp,0xc ; hook here
          0x0f,0xb6,0xc0,  // movzx eax,al
          0x85,0xc0,       // test eax,eax
          0x75, 0x0e       // jnz XXOO ; it must be 0xe, or there will be duplication
        };
        //enum { addr_offset = 0 };
        ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
        //GROWL_DWORD3(reladdr, processStartAddress, range);
        if (!addr) {
            ConsoleOutput("vnreng:Artemis1: pattern not exist");
            return false;
        }

        HookParam hp = {};
        hp.address = addr;
        hp.length_offset = 1;
        hp.offset = -0xc;
        hp.split = 0x14;
        hp.type = NO_CONTEXT | DATA_INDIRECT | USING_SPLIT; // 0x418

        //hp.address = 0x650a2f;
        //GROWL_DWORD(hp.address);

        ConsoleOutput("vnreng: INSERT Artemis1");
        NewHook(hp, "Artemis1");
        //ConsoleOutput("Artemis1");
        return true;
    }

    bool InsertArtemis2Hook()
    {
        const BYTE bytes[] = {
            // 0054461F | CC                       | int3                                    |
0x55,              // 00544620 | 55                       | push ebp                                |
0x8B, 0xEC,        // 00544621 | 8B EC                    | mov ebp,esp                             |
0x83, 0xE4, 0xF8,  // 00544623 | 83 E4 F8                 | and esp,FFFFFFF8                        |
0x6A, 0xFF,        // 00544626 | 6A FF                    | push FFFFFFFF                           |
0x68, XX4,         // 00544628 | 68 68 7C 6A 00           | push 空のつくりかた体験版_ver3.0.6A7C68           |
0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, // 0054462D | 64 A1 00 00 00 00        | mov eax,dword ptr fs:[0]                |
0x50,              // 00544633 | 50                       | push eax                                |
0x83, 0xEC, XX,  // 00544634 | 83 EC 28                 | sub esp,28                              |
0xA1, XX4,         // 00544637 | A1 F0 57 81 00           | mov eax,dword ptr ds:[8157F0]           |
0x33, 0xC4,        // 0054463C | 33 C4                    | xor eax,esp                             |
0x89, 0x44, 0x24, XX, // 0054463E | 89 44 24 20              | mov dword ptr ss:[esp+20],eax           |
0x53,              // 00544642 | 53                       | push ebx                                |
0x56,              // 00544643 | 56                       | push esi                                |
0x57,              // 00544644 | 57                       | push edi                                |
0xA1, XX4,         // 00544645 | A1 F0 57 81 00           | mov eax,dword ptr ds:[8157F0]           |
0x33, 0xC4,        // 0054464A | 33 C4                    | xor eax,esp                             |
0x50,              // 0054464C | 50                       | push eax                                |
0x8D, 0x44, 0x24, XX, // 0054464D | 8D 44 24 38              | lea eax,dword ptr ss:[esp+38]           | [esp+38]:BaseThreadInitThunk
0x64, 0xA3, 0x00, 0x00, 0x00, 0x00, // 00544651 | 64 A3 00 00 00 00        | mov dword ptr fs:[0],eax                |
0x8B, 0xF1,        // 00544657 | 8B F1                    | mov esi,ecx                             |
0x8B, 0x5D, 0x08,  // 00544659 | 8B 5D 08                 | mov ebx,dword ptr ss:[ebp+8]            |
0x8B, 0x4D, 0x0C   // 0054465C | 8B 4D 0C                 | mov ecx,dword ptr ss:[ebp+C]            | ecx:DbgUiRemoteBreakin, [ebp+C]:BaseThreadInitThunk
        };
        enum { addr_offset = 0 }; // distance to the beginning of the function, which is 0x55 (push ebp)
        ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
        if (!addr) {
            ConsoleOutput("vnreng:Artemis2: pattern not found");
            return false;
        }
        addr += addr_offset;
        enum { push_ebp = 0x55 }; // beginning of the function
        if (*(BYTE*)addr != push_ebp) {
            ConsoleOutput("vnreng:Artemis2: beginning of the function not found");
            return false;
        }

        HookParam hp = {};
        hp.address = addr;
        hp.offset = 4;
        hp.type = USING_STRING | NO_CONTEXT;

        ConsoleOutput("vnreng: INSERT Artemis2");
        NewHook(hp, "Artemis2");

        // Artikash 1/1/2019: Recent games seem to use utf8 encoding instead, other than that the hook is identical.
        // Not sure how to differentiate which games are sjis/utf8 so insert both
        hp.address = addr + 6;
        hp.offset = pusha_ebp_off - 4;
        hp.index = 8; // ebp was also pushed
        hp.type = USING_UTF8 | USING_STRING | DATA_INDIRECT | NO_CONTEXT;
        NewHook(hp, "Artemis2");
        //ConsoleOutput("Artemis2");
        return true;
    }

    bool InsertArtemisHook()
    {
        return InsertArtemis1Hook() || InsertArtemis2Hook();
    }

    /**
     *  jichi 1/2/2014: Taskforce2 Engine
     *
     *  Examples:
     *  神�仮)-カミサマカヂ�カリ- 路地裏繚乱編 (1.1)
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
     *  [131129] [Digital Cute] オトメスイッ� -OtomeSwitch- �彼が持ってる彼女のリモコン(1.1)
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
        enum { addr_offset = sizeof(bytes) - 2 };
        ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
        //GROWL_DWORD3(reladdr, processStartAddress, range);
        if (!addr) {
            ConsoleOutput("vnreng:Taskforce2: pattern not exist");
            return false;
        }

        HookParam hp = {};
        hp.address = addr + addr_offset;
        hp.offset = -0xc; // text in ecx
        hp.type = BIG_ENDIAN | USING_STRING; // 0x41

        //GROWL_DWORD(hp.address);
        //hp.address = 0x1948e9 + processStartAddress;

        ConsoleOutput("vnreng: INSERT Taskforce2");
        NewHook(hp, "Taskforce2");
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
     *    processStartAddress = 10e0000 (variant)
     *    hook_addr = processStartAddress + reladdr = 0xe55332
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
     *    processStartAddress: 0x12b0000
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
     *    processStartAddress: 0x12f0000
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
        bool FindRejetHook(LPCVOID pattern, DWORD pattern_size, DWORD hook_off, DWORD hook_offset, LPCSTR hook_name = "Rejet")
        {
            // Offset to the function call from the beginning of the function
            //enum { addr_offset = 0x21 }; // Type1: hex(0x01185332-0x01185311)
            //const BYTE pattern[] = {    // Type1: Function start
            //  0xff,0xf0,      // 01185311   . fff0           push eax  ; beginning of a new function
            //  0x0f,0xc1,0x11, // 01185313   . 0fc111         xadd dword ptr ds:[ecx],edx
            //  0x4a,           // 01185316   . 4a             dec edx
            //  0x85,0xd2,      // 01185317   . 85d2           test edx,edx
            //  0x0f,0x8f       // 01185319   . 0f8f 45020000  jg DotKares.01185564
            //};
            //GROWL_DWORD(processStartAddress);
            ULONG addr = processStartAddress; //- sizeof(pattern);
            do {
                //addr += sizeof(pattern); // ++ so that each time return diff address
                ULONG range = min(processStopAddress - addr, MAX_REL_ADDR);
                addr = MemDbg::findBytes(pattern, pattern_size, addr, addr + range);
                if (!addr) {
                    //ITH_MSG(L"failed");
                    ConsoleOutput("vnreng:Rejet: pattern not found");
                    return false;
                }

                addr += hook_off;
                //GROWL_DWORD(addr);
                //GROWL_DWORD(*(DWORD *)(addr-3));
                //const BYTE hook_ins[] = {
                //  /*0x8b,*/0x74,0x24, 0x20,  //    mov esi,dword ptr ss:[esp+0x20]
                //  0xe8 //??,??,??,??, 01357af9  e8 7283fbff call DotKares.0130fe70 ; jichi: hook here
                //};
            } while (0xe8202474 != *(DWORD*)(addr - 3));

            ConsoleOutput("vnreng: INSERT Rejet");
            HookParam hp = {};
            hp.address = addr; //- 0xf;
            hp.type = NO_CONTEXT | DATA_INDIRECT | FIXING_SPLIT;
            hp.length_offset = 1;
            hp.offset = hook_offset;
            //hp.offset = -0x8; // Type1
            //hp.offset = -0xc; // Type2

            NewHook(hp, hook_name);
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
            enum { addr_offset = 0x21 }; // Type1: hex(0x01185332-0x01185311)
            enum { hook_offset = -0x8 }; // hook parameter
            return FindRejetHook(bytes, sizeof(bytes), addr_offset, hook_offset);
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
            enum { addr_offset = 0x27 }; // Type2: hex(0x0133CEC7-0x0133CEA0) = hex(0x01357af9-0x1357ad2)
            enum { hook_offset = -0xc }; // hook parameter
            return FindRejetHook(bytes, sizeof(bytes), addr_offset, hook_offset);
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
            //enum { addr_offset = 0x27 }; // Type2: hex(0x0133CEC7-0x0133CEA0) = hex(0x01357af9-0x1357ad2)
            enum { hook_offset = -0xc }; // hook parameter
            ULONG addr = processStartAddress; //- sizeof(bytes);
            while (true) {
                //addr += sizeof(bytes); // ++ so that each time return diff address
                ULONG range = min(processStopAddress - addr, MAX_REL_ADDR);
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
                    if (*(WORD*)(addr + i - 1) == 0x6852 && *(BYTE*)(addr + i + 5) == 0xe8) // 0118534B-01185346
                        break;
                if (i < stop) {
                    addr += i;
                    break;
                }
            } //while(0xe8202474 != *(DWORD *)(addr - 3));

            //GROWL_DWORD(addr - processStartAddress); // = 0xb3578 for 剣が君

            ConsoleOutput("vnreng: INSERT Rejet");
            // The same as type2
            HookParam hp = {};
            hp.address = addr; //- 0xf;
            hp.type = NO_CONTEXT | DATA_INDIRECT | FIXING_SPLIT;
            hp.length_offset = 1;
            hp.offset = hook_offset;
            //hp.offset = -0x8; // Type1
            //hp.offset = -0xc; // Type2

            NewHook(hp, "Rejet");
            return true;
        }
    } // unnamed Rejet

    bool InsertRejetHook()
    {
        return InsertRejetHook2() || InsertRejetHook1() || InsertRejetHook3();
    } // insert hook2 first, since 2's pattern seems to be more unique

/**
 *  jichi 4/1/2014: Insert AU hook
 *  Sample games:
 *  英雼�戦姫: /HBN-8*4@4AD807
 *  英雼�戦姫GOLD: /HB-8*4@4ADB50 (alternative)
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
 *  004ad771  |. 0f87 37020000  |ja 英雼�戦.004ad9ae
 *  004ad777  |. ff2485 2cda4a0>|jmp dword ptr ds:[eax*4+0x4ada2c]
 *  004ad77e  |> 83bf c4000000 >|cmp dword ptr ds:[edi+0xc4],0x1         ;  case 1 of switch 004ad76d
 *  004ad785  |. 75 35          |jnz short 英雼�戦.004ad7bc
 *  004ad787  |. 39af c8000000  |cmp dword ptr ds:[edi+0xc8],ebp
 *  004ad78d  |. 72 08          |jb short 英雼�戦.004ad797
 *  004ad78f  |. 8b87 b4000000  |mov eax,dword ptr ds:[edi+0xb4]
 *  004ad795  |. eb 06          |jmp short 英雼�戦.004ad79d
 *  004ad797  |> 8d87 b4000000  |lea eax,dword ptr ds:[edi+0xb4]
 *  004ad79d  |> 0fb608         |movzx ecx,byte ptr ds:[eax]
 *  004ad7a0  |. 51             |push ecx
 *  004ad7a1  |. e8 d15b2a00    |call 英雼�戦.00753377
 *  004ad7a6  |. 83c4 04        |add esp,0x4
 *  004ad7a9  |. 85c0           |test eax,eax
 *  004ad7ab  |. 74 0f          |je short 英雼�戦.004ad7bc
 *  004ad7ad  |. 8d5424 20      |lea edx,dword ptr ss:[esp+0x20]
 *  004ad7b1  |. 52             |push edx
 *  004ad7b2  |. b9 88567a00    |mov ecx,英雼�戦.007a5688
 *  004ad7b7  |. e8 a40cf6ff    |call 英雼�戦.0040e460
 *  004ad7bc  |> 8b8424 e400000>|mov eax,dword ptr ss:[esp+0xe4]
 *  004ad7c3  |. 8a48 01        |mov cl,byte ptr ds:[eax+0x1]
 *  004ad7c6  |. 84c9           |test cl,cl
 *  004ad7c8  |. 75 2e          |jnz short 英雼�戦.004ad7f8
 *  004ad7ca  |. 8d9f b0000000  |lea ebx,dword ptr ds:[edi+0xb0]
 *  004ad7d0  |. be ac6e7a00    |mov esi,英雼�戦.007a6eac
 *  004ad7d5  |. 8bcb           |mov ecx,ebx
 *  004ad7d7  |. e8 e40af6ff    |call 英雼�戦.0040e2c0
 *  004ad7dc  |. 84c0           |test al,al
 *  004ad7de  |. 0f84 ca010000  |je 英雼�戦.004ad9ae
 *  004ad7e4  |. be a86e7a00    |mov esi,英雼�戦.007a6ea8
 *  004ad7e9  |. 8bcb           |mov ecx,ebx
 *  004ad7eb  |. e8 d00af6ff    |call 英雼�戦.0040e2c0
 *  004ad7f0  |. 84c0           |test al,al
 *  004ad7f2  |. 0f84 b6010000  |je 英雼�戦.004ad9ae
 *  004ad7f8  |> 6a 00          |push 0x0
 *  004ad7fa  |. 8d8f b0000000  |lea ecx,dword ptr ds:[edi+0xb0]
 *  004ad800  |. 83c8 ff        |or eax,0xffffffff
 *  004ad803  |. 8d5c24 24      |lea ebx,dword ptr ss:[esp+0x24]
 *  004ad807  |. e8 740cf6ff    |call 英雼�戦.0040e480     ; jichi: hook here
 *  004ad80c  |. e9 9d010000    |jmp 英雼�戦.004ad9ae
 *  004ad811  |> 8b8c24 e400000>|mov ecx,dword ptr ss:[esp+0xe4]         ;  case 4 of switch 004ad76d
 *  004ad818  |. 8039 00        |cmp byte ptr ds:[ecx],0x0
 *  004ad81b  |. 0f84 8d010000  |je 英雼�戦.004ad9ae
 *  004ad821  |. b8 04000000    |mov eax,0x4
 *  004ad826  |. b9 c86e7a00    |mov ecx,英雼�戦.007a6ec8                   ;  ascii "<br>"
 *  004ad82b  |. 8d5424 20      |lea edx,dword ptr ss:[esp+0x20]
 *  004ad82f  |. e8 3c0df6ff    |call 英雼�戦.0040e570
 *  004ad834  |. e9 75010000    |jmp 英雼�戦.004ad9ae
 *  004ad839  |> 8bbf b4000000  |mov edi,dword ptr ds:[edi+0xb4]         ;  case 5 of switch 004ad76d
 */
    bool InsertTencoHook()
    {
        const BYTE bytes[] = {
          0x6a, 0x00,                     // 004ad7f8  |> 6a 00          |push 0x0
          0x8d,0x8f, 0xb0,0x00,0x00,0x00, // 004ad7fa  |. 8d8f b0000000  |lea ecx,dword ptr ds:[edi+0xb0]
          0x83,0xc8, 0xff,                // 004ad800  |. 83c8 ff        |or eax,0xffffffff
          0x8d,0x5c,0x24, 0x24,           // 004ad803  |. 8d5c24 24      |lea ebx,dword ptr ss:[esp+0x24]
          0xe8 //740cf6ff                 // 004ad807  |. e8 740cf6ff    |call 英雼�戦.0040e480     ; jichi: hook here
        };
        enum { addr_offset = sizeof(bytes) - 1 };
        ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
        //reladdr = 0x4ad807;
        if (!addr) {
            ConsoleOutput("vnreng:Tenco: pattern not found");
            return false;
        }

        HookParam hp = {};
        hp.address = addr + addr_offset;
        hp.length_offset = 1;
        hp.index = 4;
        hp.offset = -0xc;
        hp.type = NO_CONTEXT | DATA_INDIRECT;

        ConsoleOutput("vnreng: INSERT Tenco");
        NewHook(hp, "Tenco");
        return true;
    }

    /**
     *  jichi 4/1/2014: Insert AOS hook
     *  About 彩斤�: http://erogetrailers.com/brand/165
     *  About AOS: http://asmodean.reverse.net/pages/exaos.html
     *
     *  Sample games:
     *
     *  [140228] [Sugar Pot] 恋する少女と想�キセキ V1.00 H-CODE by �쿿
     *  - /HB8*0@3C2F0:恋する少女と想�キセキ.exe
     *  - /HBC*0@3C190:恋する少女と想�キセキ.exe
     *
     *  [120224] [Sugar Pot]  ヂ�モノツキ
     *
     *  LiLiM games
     *
     *  /HB8*0@3C2F0:恋する少女と想�キセ
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
     *  00e3c31d  |. 74 6b                      je short 恋する�00e3c38a
     *  00e3c31f  |. 8bd9                       mov ebx,ecx
     *  00e3c321  |. 85db                       test ebx,ebx
     *  00e3c323  |. 74 17                      je short 恋する�00e3c33c
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
     *  00e3c356  |. 74 32                      je short 恋する�00e3c38a
     */

    bool InsertAOS1Hook()
    {
        // jichi 4/2/2014: The starting of this function is different from ヂ�モノツキ
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
        //enum { addr_offset = 0 };

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
        enum { addr_offset = 0x00e3c2f0 - 0x00e3c33c }; // distance to the beginning of the function, which is 0x51 (push ecx)
        ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
        //GROWL(reladdr);
        if (!addr) {
            ConsoleOutput("vnreng:AOS1: pattern not found");
            return false;
        }
        addr += addr_offset;
        //GROWL(addr);
        enum { push_ecx = 0x51 }; // beginning of the function
        if (*(BYTE*)addr != push_ecx) {
            ConsoleOutput("vnreng:AOS1: beginning of the function not found");
            return false;
        }

        HookParam hp = {};
        hp.address = addr;
        hp.length_offset = 1;
        hp.offset = 8;
        hp.type = DATA_INDIRECT;

        ConsoleOutput("vnreng: INSERT AOS1");
        NewHook(hp, "AOS1");
        return true;
    }

    bool InsertAOS2Hook()
    {
        const BYTE bytes[] = {
          0x51,                  // 00C4E7E0  /$  51            PUSH ECX ; mireado: hook here, function begins
          0x33,0xc0,             // 00C4E7E1  |.  33C0          XOR EAX,EAX
          0x53,                  // 00C4E7E3  |.  53            PUSH EBX
          0x55,                  // 00C4E7E4  |.  55            PUSH EBP
          0x8b,0x2d//, XX4,           // 00C4E7E5  |.  8B2D 40A3CF00 MOV EBP,DWORD PTR DS:[0CFA340] ; mireado: some time changing 40A3CF00 => 40A3C000
          //0x89,0x07,             // 00C4E7EB  |.  8907          MOV DWORD PTR DS:[EDI],EAX
          //0x89,0x47, 0x04       // 00C4E7ED  |.  8947 04       MOV DWORD PTR DS:[EDI+4],EAX
          //0x56,                  // 00C4E7F0  |.  56            PUSH ESI
          //0x8b,0x75, 0x44        // 00C4E7F1  |.  8B75 44       MOV ESI,DWORD PTR SS:[EBP+44]
        };

        enum { addr_offset = 0 }; // distance to the beginning of the function, which is 0x51 (push ecx)
        ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
        //GROWL(reladdr);
        if (!addr) {
            ConsoleOutput("vnreng:AOS2: pattern not found");
            return false;
        }
        addr += addr_offset;
        //GROWL(addr);
        enum { push_ecx = 0x51 }; // beginning of the function
        if (*(BYTE*)addr != push_ecx) {
            ConsoleOutput("vnreng:AOS2: beginning of the function not found");
            return false;
        }

        HookParam hp = {};
        hp.address = addr;
        hp.length_offset = 1;
        hp.offset = 8;
        hp.type = DATA_INDIRECT;

        ConsoleOutput("vnreng: INSERT AOS2");
        NewHook(hp, "AOS2");
        return true;
    }

    bool InsertAOSHook()
    {
        return InsertAOS1Hook() || InsertAOS2Hook();
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
      *  17 スク水不要� /HA4@4AD140
      *  18 ななちも�とぁ�しょ: /HA4@5104A0
      *  19 発惁�んこぁ�� /HA4@51D720
      *  20 わたし�たまごさ� /HA4@4968E0
      *  21 修学旡�夜更かし� /HA4@49DC00
      *  22 おぼえたてキヂ�: /HA4@49DDB0
      *  23 ちっさい巫女さんSOS: /HA4@4B4AA0
      *  24 はじめてのお�ろやさん: /HA4@4B5600
      *  25 はきわすれ愛好� /HA4@57E360
      *  26 朝っぱらから発惮�� /HA4@57E360
      *  27 となり�ヴァンパイア: /HA4@5593B0
      *  28 麦わら帽子と水辺の妖精: /HA4@5593B0
      *  29 海と温泉と夏休み: /HA4@6DE8E0
      *  30 駏�子屋さん繁盛� /HA4@6DEC90
      *  31 浴衣の下�… �神社で発見�ノ�パン少女 /HA4@6DEC90
      *  32 プ�ルのじか�スク水不要�: /HA4@62AE10
      *  33 妹のお泊まり� /HA4@6087A0
      *  34 薝�少女: /HA4@6087A0
      *  35 あや�Princess Intermezzo: /HA4@609BF0
      *
      *  SG01 男湯�: /HA4@6087A0
      *
      *  c71 真�の大晦日CD: /HA4@516b50
      *  c78 sol-fa-soft真夏�お気楽CD: /HA4@6DEC90
      *
      *  Example: 35 あや�Princess Intermezzo: /HA4@609BF0
      *  - addr: 6331376 = 0x609bf0
      *  - length_offset: 1
      *  - off: 4
      *  - type: 4
      *
      *  ASCII: あや� addr_offset = -50
      *  Function starts
      *  00609bef  /> cc             int3
      *  00609bf0  /> 55             push ebp
      *  00609bf1  |. 8bec           mov ebp,esp
      *  00609bf3  |. 64:a1 00000000 mov eax,dword ptr fs:[0]
      *  00609bf9  |. 6a ff          push -0x1
      *  00609bfb  |. 68 e1266300    push あや�006326e1
      *  00609c00  |. 50             push eax
      *  00609c01  |. 64:8925 000000>mov dword ptr fs:[0],esp
      *  00609c08  |. 81ec 80000000  sub esp,0x80
      *  00609c0e  |. 53             push ebx
      *  00609c0f  |. 8b5d 08        mov ebx,dword ptr ss:[ebp+0x8]
      *  00609c12  |. 57             push edi
      *  00609c13  |. 8bf9           mov edi,ecx
      *  00609c15  |. 8b07           mov eax,dword ptr ds:[edi]
      *  00609c17  |. 83f8 02        cmp eax,0x2
      *  00609c1a  |. 75 1f          jnz short あや�00609c3b
      *  00609c1c  |. 3b5f 40        cmp ebx,dword ptr ds:[edi+0x40]
      *  00609c1f  |. 75 1a          jnz short あや�00609c3b
      *  00609c21  |. 837f 44 00     cmp dword ptr ds:[edi+0x44],0x0
      *  00609c25  |. 74 14          je short あや�00609c3b
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
      *  WideChar: こいな�小田舎で初恋x中出しセクシャルライ�, addr_offset = -53
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
      *  WideChar: 祝福�鐘�音は、桜色の風と共に, addr_offset = -50,
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
        PcHooks::hookOtherPcFunctions();
        //const BYTE bytes[] = {
        //  0x53,                    // 00609c0e  |. 53             push ebx
        //  0x8b,0x5d,0x08,          // 00609c0f  |. 8b5d 08        mov ebx,dword ptr ss:[ebp+0x8]
        //  0x57,                    // 00609c12  |. 57             push edi
        //  0x8b,0xf9,               // 00609c13  |. 8bf9           mov edi,ecx
        //  0x8b,0x07,               // 00609c15  |. 8b07           mov eax,dword ptr ds:[edi]
        //  0x83,0xf8, 0x02,         // 00609c17  |. 83f8 02        cmp eax,0x2
        //  0x75, 0x1f,              // 00609c1a  |. 75 1f          jnz short あや�00609c3b
        //  0x3b,0x5f, 0x40,         // 00609c1c  |. 3b5f 40        cmp ebx,dword ptr ds:[edi+0x40]
        //  0x75, 0x1a,              // 00609c1f  |. 75 1a          jnz short あや�00609c3b
        //  0x83,0x7f, 0x44, 0x00,   // 00609c21  |. 837f 44 00     cmp dword ptr ds:[edi+0x44],0x0
        //  0x74, 0x14,              // 00609c25  |. 74 14          je short あや�00609c3b
        //};
        //enum { addr_offset = 0x00609bf0 - 0x00609c0e }; // distance to the beginning of the function

        const BYTE bytes[] = {
          0x74, 0x14,     // 00609c25  |. 74 14          je short あや�00609c3b
          0x5f,           // 00609c27  |. 5f             pop edi
          0xb0, 0x01,     // 00609c28  |. b0 01          mov al,0x1
          0x5b,           // 00609c2a  |. 5b             pop ebx
          0x8b,0x4d, 0xf4 // 00609c2b  |. 8b4d f4        mov ecx,dword ptr ss:[ebp-0xc]
        };
        enum { // distance to the beginning of the function
            addr_offset_A = 0x00609bf0 - 0x00609c25   // -53
            , addr_offset_W = 0x00406540 - 0x00406572 // -50
        };
        ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
        ULONG start = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
        if (!start) {
            ConsoleOutput("vnreng:ScenarioPlayer: pattern not found");
            return false;
        }

        DWORD addr = MemDbg::findEnclosingAlignedFunction(start, 80); // range is around 50, use 80

        enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
        if (!addr || *(BYTE*)addr != push_ebp) {
            ConsoleOutput("vnreng:ScenarioPlayer: pattern found but the function offset is invalid");
            return false;
        }

        HookParam hp = {};
        hp.address = addr;
        hp.length_offset = 1;
        hp.offset = 4;
        if (addr - start == addr_offset_W) {
            // Artikash 8/18/2018: can't figure out how to tell apart which hook is needed, so alert user
            // (The method used to tell the hooks apart previously fails on https://vndb.org/v19713)

            hp.type = USING_UNICODE;
            ConsoleOutput("vnreng: INSERT ScenarioPlayerW");
            NewHook(hp, "ScenarioPlayerW");
        }
        else {
            hp.type = BIG_ENDIAN; // 4
            ConsoleOutput("vnreng: INSERT ScenarioPlayerA");
            NewHook(hp, "ScenarioPlayerA");
        }
        ConsoleOutput("Text encoding might be wrong: try changing it if this hook finds garbage!");
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
     *  妖恋愛奭�神サマ�堕し方/HS4*0@40D160
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
        //ULONG addr = Util::FindCallAndEntryAbs((DWORD)CreateFontA, processStopAddress - processStartAddress, processStartAddress, 0xec8b);

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
          0xe8//, 0x00,0xfa,0x06,0x00   // 0040d1e9  |. e8 00fa0600        call <jmp.&gdi32.CreateFontA>   ; \createfonta
        };
        enum { addr_offset = 0x0040d160 - 0x0040d1c6 }; // distance to the beginning of the function
        ULONG range = min(processStopAddress - processStartAddress, MAX_REL_ADDR);
        ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStartAddress + range);
        //GROWL_DWORD(reladdr);
        if (!addr) {
            ConsoleOutput("vnreng:MarineHeart: pattern not found");
            return false;
        }

        addr += addr_offset;
        //addr = 0x40d160;
        //GROWL_DWORD(addr);
        enum : BYTE { push_ebp = 0x55 };  // 011d4c80  /$ 55             push ebp
        if (*(BYTE*)addr != push_ebp) {
            ConsoleOutput("vnreng:MarineHeart: pattern found but the function offset is invalid");
            return false;
        }

        HookParam hp = {};
        hp.address = addr;
        hp.offset = 4;
        hp.type = USING_STRING | DATA_INDIRECT; // = 9

        ConsoleOutput("vnreng: INSERT MarineHeart");
        NewHook(hp, "MarineHeart");
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

    static void SpecialHookElf(DWORD esp_base, HookParam*, BYTE, DWORD* data, DWORD* split, DWORD* len)
    {
        //DWORD arg1 = *(DWORD *)(esp_base + 0x4);
        DWORD arg1 = argof(1, esp_base);
        DWORD arg2_scene = arg1 + 4 * 5,
            arg2_chara = arg1 + 4 * 10;
        DWORD text; //= 0; // This variable will be killed
        if (*(DWORD*)arg2_scene == 0) {
            text = *(DWORD*)(arg2_scene + 4 * 3);
            if (!text || ::IsBadReadPtr((LPCVOID)text, 1)) // Text from scenario could be bad when open backlog while the character is speaking
                return;
            *split = 1;
        }
        else if (*(DWORD*)arg2_chara == 0) {
            text = arg2_chara + 4 * 3;
            *split = 2;
        }
        else
            return;
        //if (text && text < MemDbg::UserMemoryStopAddress) {
        *len = _elf_strlen((LPCSTR)text); // in case the text is bad but still readable
        //*len = ::strlen((LPCSTR)text);
        *data = text;
    }

    /**
     *  jichi 5/31/2014: elf's
     *  Type1: SEXヂ�ーチャー剛史 trial, reladdr = 0x2f0f0, 2 parameters
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

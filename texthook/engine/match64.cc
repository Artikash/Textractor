#include "match.h"
#include "main.h"
#include "texthook.h"
#include "native/pchooks.h"
#include "mono/monoobject.h"
#include "mono/funcinfo.h"
#include "engine.h"
#include "util.h"
#include "cpputil/cppcstring.h"

// Warning: The offset in ITH has -4 offset comparing to pusha and AGTH
enum pusha_off
{
	pusha_rax_off = -0xC,
	pusha_rbx_off = -0x14,
	pusha_rcx_off = -0x1c,
	pusha_rdx_off = -0x24,
	pusha_rsp_off = -0x2c,
	pusha_rbp_off = -0x34,
	pusha_rsi_off = -0x3c,
	pusha_rdi_off = -0x44,
	pusha_r8_off  = -0x4c,
	pusha_r9_off  = -0x54,
	pusha_r10_off = -0x5c,
	pusha_r11_off = -0x64,
	pusha_r12_off = -0x6c,
	pusha_r13_off = -0x74,
	pusha_r14_off = -0x7c,
	pusha_r15_off = -0x84,
	pusha_off     = -0x8c // pushad offset
};

#define retof(rsp_base)         *(uintptr_t *)(rsp_base) // return address
#define regof(name, rsp_base)   *(uintptr_t *)((rsp_base) + pusha_##name##_off - 4)
#define argof(count, rsp_base)  *(uintptr_t *)((rsp_base) + 4 * (count)) // starts from 1 instead of 0

enum { VNR_TEXT_CAPACITY = 1500 }; // estimated max number of bytes allowed in VNR, slightly larger than VNR's text limit (1000)

namespace { // unnamed helpers

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
DWORD text_buffer_length;

// 7/29/2014 jichi: I should move these functions to different files
// String utilities
// Return the address of the first non-zero address
LPCSTR reverse_search_begin(const char *s, int maxsize = VNR_TEXT_CAPACITY)
{
  if (*s)
    for (int i = 0; i < maxsize; i++, s--)
      if (!*s)
        return s + 1;
  return nullptr;
}

bool all_ascii(const char *s, int maxsize = VNR_TEXT_CAPACITY)
{
  if (s)
    for (int i = 0; i < maxsize && *s; i++, s++)
      if ((BYTE)*s > 127) // unsigned char
        return false;
  return true;
}

bool all_ascii(const wchar_t *s, int maxsize = VNR_TEXT_CAPACITY)
{
  if (s)
    for (int i = 0; i < maxsize && *s; i++, s++)
      if (*s > 127) // unsigned char
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
  for (char *cur = (char *)::memchr(str, ch, len);
       (cur && --len && (curlen = len - (cur - str)));
       cur = (char *)::memchr(cur, ch, curlen))
    ::memmove(cur, cur + 1, curlen);
  *size = len;
}

void WideCharFilter(wchar_t *str, size_t *size, wchar_t ch)
{
  size_t len = *size / 2,
         curlen;
  for (wchar_t *cur = cpp_wcsnchr(str, ch, len);
       (cur && --len && (curlen = len - (cur - str)));
       cur = cpp_wcsnchr(cur, ch, curlen))
    ::memmove(cur, cur + 1, 2 * curlen);
  *size = len * 2;
}

void CharsFilter(char *str, size_t *size, const char *chars)
{
  size_t len = *size,
         curlen;
  for (char *cur = cpp_strnpbrk(str, chars, len);
       (cur && --len && (curlen = len - (cur - str)));
       cur = cpp_strnpbrk(cur, chars, curlen))
    ::memmove(cur, cur + 1, curlen);
  *size = len;
}

void WideCharsFilter(wchar_t *str, size_t *size, const wchar_t *chars)
{
  size_t len = *size / 2,
         curlen;
  for (wchar_t *cur = cpp_wcsnpbrk(str, chars, len);
       (cur && --len && (curlen = len - (cur - str)));
       cur = cpp_wcsnpbrk(cur, chars, curlen))
    ::memmove(cur, cur + 1, 2 * curlen);
  *size = len * 2;
}

void StringFilter(char *str, size_t *size, const char *remove, size_t removelen)
{
  size_t len = *size,
         curlen;
  for (char *cur = cpp_strnstr(str, remove, len);
       (cur && (len -= removelen) && (curlen = len - (cur - str)));
       cur = cpp_strnstr(cur, remove, curlen))
    ::memmove(cur, cur + removelen, curlen);
  *size = len;
}

void WideStringFilter(wchar_t *str, size_t *size, const wchar_t *remove, size_t removelen)
{
  size_t len = *size / 2,
         curlen;
  for (wchar_t *cur = cpp_wcsnstr(str, remove, len);
       (cur && (len -= removelen) && (curlen = len - (cur - str)));
       cur = cpp_wcsnstr(cur, remove, curlen))
    ::memmove(cur, cur + removelen, 2 * curlen);
  *size = len * 2;
}

void StringFilterBetween(char *str, size_t *size, const char *fr, size_t frlen, const char *to, size_t tolen)
{
  size_t len = *size,
         curlen;
  for (char *cur = cpp_strnstr(str, fr, len);
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

void WideStringFilterBetween(wchar_t *str, size_t *size, const wchar_t *fr, size_t frlen, const wchar_t *to, size_t tolen)
{
  size_t len = *size / 2,
         curlen;
  for (wchar_t *cur = cpp_wcsnstr(str, fr, len);
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

void StringCharReplacer(char *str, size_t *size, const char *src, size_t srclen, char ch)
{
  size_t len = *size,
         curlen;
  for (char *cur = cpp_strnstr(str, src, len);
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

void WideStringCharReplacer(wchar_t *str, size_t *size, const wchar_t *src, size_t srclen, wchar_t ch)
{
  size_t len = *size / 2,
         curlen;
  for (wchar_t *cur = cpp_wcsnstr(str, src, len);
       cur && len;
       cur = cpp_wcsnstr(cur, src, curlen)) {
    *cur++ = ch;
    len -= srclen - 1;
    curlen = len - (cur - str);
    if (curlen == 0)
      break;
    ::memmove(cur, cur + srclen -1, 2 * curlen);
  }
  *size = len * 2;
}

// NOTE: I assume srclen >= dstlen
void StringReplacer(char *str, size_t *size, const char *src, size_t srclen, const char *dst, size_t dstlen)
{
  size_t len = *size,
         curlen;
  for (char *cur = cpp_strnstr(str, src, len);
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

void WideStringReplacer(wchar_t *str, size_t *size, const wchar_t *src, size_t srclen, const wchar_t *dst, size_t dstlen)
{
  size_t len = *size / 2,
         curlen;
  for (wchar_t *cur = cpp_wcsnstr(str, src, len);
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
bool NewLineWideStringFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  WideStringFilter(reinterpret_cast<LPWSTR>(data), reinterpret_cast<size_t *>(size),
      L"\\n", 2);
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

namespace Engine
{
	enum : DWORD { X64_MAX_REL_ADDR = 0x00300000 };
	/** Artikash 6/7/2019
*   PPSSPP JIT code has pointers, but they are all added to an offset before being used.
	Find that offset so that hook searching works properly.
	To find the offset, find a page of mapped memory with size 0x1f00000, read and write permissions, take its address and subtract 0x8000000.
	The above is useful for emulating PSP hardware, so unlikely to change between versions.
*/
	bool FindPPSSPP()
	{
		bool found = false;
		SYSTEM_INFO systemInfo;
		GetNativeSystemInfo(&systemInfo);
		for (BYTE* probe = NULL; probe < systemInfo.lpMaximumApplicationAddress;)
		{
			MEMORY_BASIC_INFORMATION info;
			if (!VirtualQuery(probe, &info, sizeof(info)))
			{
				probe += systemInfo.dwPageSize;
			}
			else
			{
				if (info.RegionSize == 0x1f00000 && info.Protect == PAGE_READWRITE && info.Type == MEM_MAPPED)
				{
					found = true;
					ConsoleOutput("Textractor: PPSSPP memory found: searching for hooks should yield working hook codes");
					// PPSSPP 1.8.0 compiles jal to sub dword ptr [r14+0x360],??
					memcpy(spDefault.pattern, Array<BYTE>{ 0x41, 0x83, 0xae, 0x60, 0x03, 0x00, 0x00 }, spDefault.length = 7);
					spDefault.offset = 0;
					spDefault.minAddress = 0;
					spDefault.maxAddress = -1ULL;
					spDefault.padding = (uintptr_t)probe - 0x8000000;
					spDefault.hookPostProcessor = [](HookParam& hp)
					{
						hp.type |= NO_CONTEXT | USING_SPLIT | SPLIT_INDIRECT;
						hp.split = -0x80; // r14
						hp.split_index = -8; // this is where PPSSPP 1.8.0 stores its return address stack
					};
				}
				probe += info.RegionSize;
			}
		}
		return found;
	}

	bool InsertMonoHooks(HMODULE module)
	{
		auto SpecialHookMonoString = nullptr;
		static HMODULE mono = module;
		bool ret = false;
		for (auto func : Array<MonoFunction>{ MONO_FUNCTIONS_INITIALIZER })
		{
			HookParam hp = {};
			if (!(hp.address = (uintptr_t)GetProcAddress(mono, func.functionName))) continue;
			hp.type = HOOK_EMPTY;
			NewHook(hp, "Mono Searcher");
			ret = true;
		}
		/* Artikash 2/13/2019:
		How to hook Mono/Unity3D:
		Find all standard function prologs in memory with write/execute permission: these represent possible JIT compiled functions
		Then use Mono APIs to reflect what these functions are, and hook them if they are string member functions
		Mono calling convention uses 'this' as first argument
		Must be dynamic hook bootstrapped from other mono api or mono_domain_get won't work
		*/
		trigger_fun = [](LPVOID addr, DWORD, DWORD)
		{
			static auto getDomain = (MonoDomain*(*)())GetProcAddress(mono, "mono_domain_get");
			static auto getJitInfo = (MonoObject*(*)(MonoDomain*, uintptr_t))GetProcAddress(mono, "mono_jit_info_table_find");
			static auto getName = (char*(*)(uintptr_t))GetProcAddress(mono, "mono_pmip");
			if (!getDomain || !getName || !getJitInfo) goto failed;
			static auto domain = getDomain();
			if (!domain) goto failed;
			ConsoleOutput("Textractor: Mono Dynamic ENTER (hooks = %s)", *loadedConfig ? loadedConfig : "brute force");
			const BYTE prolog1[] = { 0x55, 0x48, 0x8b, 0xec };
			const BYTE prolog2[] = { 0x48, 0x83, 0xec };
			for (auto [prolog, size] : Array<const BYTE*, size_t>{ { prolog1, sizeof(prolog1) }, { prolog2, sizeof(prolog2) } })
			for (auto addr : Util::SearchMemory(prolog, size, PAGE_EXECUTE_READWRITE))
			{
				[](uint64_t addr)
				{
					__try
					{
						if (getJitInfo(domain, addr))
							if (char* name = getName(addr))
								if (strstr(name, "0x0") && ShouldMonoHook(name))
								{
									HookParam hp = {};
									hp.address = addr;
									hp.type = USING_STRING | USING_UNICODE | FULL_STRING;
									if (!*loadedConfig) hp.type |= KNOWN_UNSTABLE;
									hp.offset = -0x20; // rcx
									hp.padding = 20;
									char nameForUser[HOOK_NAME_SIZE] = {};
									strncpy_s(nameForUser, name + 1, HOOK_NAME_SIZE - 1);
									if (char* end = strstr(nameForUser, " + 0x0")) *end = 0;
									if (char* end = strstr(nameForUser, "{")) *end = 0;
									hp.length_fun = [](uintptr_t, uintptr_t data)
									{
										/* Artikash 6/18/2019:
										even though this should get the true length mono uses internally
										there's still some garbage picked up on https://vndb.org/v20403 demo, don't know why */
										int len = *(int*)(data - 4);
										return len > 0 && len < PIPE_BUFFER_SIZE ? len * 2 : 0;
									};
									NewHook(hp, nameForUser);
								}
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {}
				}(addr);
			}

			if (!*loadedConfig) ConsoleOutput("Textractor: Mono Dynamic used brute force: if performance issues arise, please specify the correct hook in the game configuration");
			return true;
		failed:
			ConsoleOutput("Textractor: Mono Dynamic failed");
			return true;
		};
		return ret;
	}

	// Artikash 6/23/2019: V8 (JavaScript runtime) has rcx = string** at v8::String::Write
	// sample game https://www.freem.ne.jp/dl/win/18963
	bool InsertV8Hook(HMODULE module)
	{
		auto getV8Length =  [](uintptr_t, uintptr_t data)
		{
			int len = *(int*)(data - 4);
			return len > 0 && len < PIPE_BUFFER_SIZE ? len * 2 : 0;
		};

		uint64_t addr1 = (uint64_t)GetProcAddress(module, "?Write@String@v8@@QEBAHPEAGHHH@Z"),
			// Artikash 6/7/2021: Add new hook for new version of V8 used by RPG Maker MZ
			addr2 = (uint64_t)GetProcAddress(module, "??$WriteToFlat@G@String@internal@v8@@SAXV012@PEAGHH@Z");

		if (addr1 || addr2)
		{
			std::tie(spDefault.minAddress, spDefault.maxAddress) = Util::QueryModuleLimits(module);
			spDefault.maxRecords = Util::SearchMemory(spDefault.pattern, spDefault.length, PAGE_EXECUTE, spDefault.minAddress, spDefault.maxAddress).size() * 20;
			ConsoleOutput("Textractor: JavaScript hook is known to be low quality: try searching for hooks if you don't like it");
		}
		if (addr1)
		{
			HookParam hp = {};
			hp.type = USING_STRING | USING_UNICODE | DATA_INDIRECT;
			hp.address = addr1;
			hp.offset = -0x20; // rcx
			hp.index = 0;
			hp.padding = 23;
			hp.length_fun = getV8Length;
			NewHook(hp, "JavaScript");
		}
		if (addr2)
		{
			HookParam hp = {};
			hp.type = USING_STRING | USING_UNICODE;
			hp.address = addr2;
			hp.offset = -0x20; // rcx
			hp.padding = 11;
			hp.length_fun = getV8Length;
			NewHook(hp, "JavaScript");
		}
		return addr1 || addr2;
	}

	/** Artikash 8/10/2018: Ren'py
	*
	*  Sample games: https://vndb.org/v19843 https://vndb.org/v12038 and many more OELVNs
	*
	*  Uses CPython, and links to python27.dll. PyUicodeUCS2_Format is the function used to process text.
	*  first argument. offset 0x18 from that is a wchar_t* to the actual string
	*  ebx seems to work well as the split param, not sure why
	*/
	bool InsertRenpyHook()
	{
		wchar_t python[] = L"python2X.dll", libpython[] = L"libpython2.X.dll";
		for (wchar_t* name : { python, libpython })
		{
			wchar_t* pos = wcschr(name, L'X');
			for (int pythonMinorVersion = 0; pythonMinorVersion <= 8; ++pythonMinorVersion)
			{
				*pos = L'0' + pythonMinorVersion;
				if (HMODULE module = GetModuleHandleW(name))
				{
					wcscpy_s(spDefault.exportModule, name);
					HookParam hp = {};
					hp.address = (uintptr_t)GetProcAddress(module, "PyUnicodeUCS2_Format");
					if (!hp.address)
					{
						ConsoleOutput("Textractor: Ren'py failed: failed to find PyUnicodeUCS2_Format");
						return false;
					}
					hp.offset = pusha_rcx_off -4; // rcx
					hp.index = 0x18;
					hp.length_offset = 0;
					//hp.split = pusha_rsp_off -4;
					hp.type = USING_STRING | USING_UNICODE | NO_CONTEXT | DATA_INDIRECT /* | USING_SPLIT*/;
					hp.filter_fun = [](LPVOID data, DWORD *size, HookParam *, BYTE)
					{
						static std::wstring prevText;
						auto text = reinterpret_cast<LPWSTR>(data);
						auto len = reinterpret_cast<size_t *>(size);

						if (cpp_wcsnstr(text, L"%", *len/sizeof(wchar_t)))
							return false;

						if (cpp_wcsnstr(text, L"{", *len/sizeof(wchar_t))) {
							WideStringCharReplacer(text, len, L"{i}", 3, L'\'');
							WideStringCharReplacer(text, len, L"{/i}", 4, L'\'');
							WideStringFilterBetween(text, len, L"{", 1, L"}", 1);
						}
						WideStringFilter(text, len, L"^", 2); // remove ^ followed by 1 char
						WideCharReplacer(text, len, L'\n', L' ');

						if (prevText.length()==*len/sizeof(wchar_t) && prevText.find(text, 0, *len/sizeof(wchar_t))!=std::string::npos) // Check if the string is the same as the previous one
							return false;
						prevText.assign(text, *len/sizeof(wchar_t));
						
						return true;
					};
					NewHook(hp, "Ren'py");
					return true;
				}
			}
		}
		ConsoleOutput("Textractor: Ren'py failed: failed to find python2X.dll");
		return false;
	}
	bool InsertRenpy3Hook()
	{
		//by Blu3train
		/*
		* Sample games:
		* https://vndb.org/v45820
		* https://vndb.org/v26318
		* https://vndb.org/v39954
		* https://vndb.org/r110220
		* https://vndb.org/r114981
		* https://vndb.org/v33647
		* https://vndb.org/r73160
		* https://vndb.org/v44518
		* https://vndb.org/v31994
		* https://vndb.org/r115756
		*/
		wchar_t python[] = L"python3X.dll", libpython[] = L"libpython3.X.dll";
		for (wchar_t* name : { python, libpython })
		{
			wchar_t* pos = wcschr(name, L'X');
			for (int pythonMinorVersion = 0; pythonMinorVersion <= 9; ++pythonMinorVersion)
			{
				*pos = L'0' + pythonMinorVersion;
				if (HMODULE module = GetModuleHandleW(name))
				{
					wcscpy_s(spDefault.exportModule, name);
					HookParam hp = {};
					hp.address = (uintptr_t)GetProcAddress(module, "PyUnicode_Format");
					if (!hp.address)
					{
						ConsoleOutput("Textractor: Ren'py 3 failed: failed to find PyUnicode_Format");
						return false;
					}
					hp.offset = pusha_rcx_off -4; // rcx
					hp.padding = 0x48;
					hp.length_offset = 0;
					hp.text_fun = [](DWORD rsp_base, HookParam *pHp, BYTE, DWORD* data, DWORD* split, DWORD* count)
					{
						uint64_t r10 = regof(r10, rsp_base);
						uint64_t r11 = regof(r11, rsp_base);
						if (r10==0x03FF || r11==0x03FF) {
							uint64_t rcx = regof(rcx, rsp_base);
							BYTE unicode = !(*(BYTE*)(rcx + 0x20) & 0x40); // [rcx+0x20) bit 0x40 == 0
							if (unicode) {
								*data += 0x48; //padding
								*count = wcslen((wchar_t*)*data) * sizeof(wchar_t);
								return;
							}
						}
						*count = 0;
					};
					hp.type = USING_STRING | USING_UNICODE | NO_CONTEXT;
					hp.filter_fun = [](LPVOID data, DWORD *size, HookParam *, BYTE)
					{
						auto text = reinterpret_cast<LPWSTR>(data);
						auto len = reinterpret_cast<size_t *>(size);

						if (cpp_wcsnstr(text, L"%", *len/sizeof(wchar_t)))
							return false;
						if (cpp_wcsnstr(text, L"{", *len/sizeof(wchar_t))) {
							WideStringCharReplacer(text, len, L"{i}", 3, L'\'');
							WideStringCharReplacer(text, len, L"{/i}", 4, L'\'');
							WideStringFilterBetween(text, len, L"{", 1, L"}", 1);
						}

						//CP_OEMCP -The current system OEM code page
						WideCharToMultiByte(CP_OEMCP, 0, text, -1, text_buffer, 0x1000, NULL, NULL);
						text_buffer_length = *len/sizeof(wchar_t); // saved for not unicode hook
						
						return true;
					};
					NewHook(hp, "Ren'py 3 unicode");

					hp.address += 6;
					hp.padding = 0x30;
					hp.text_fun = [](DWORD rsp_base, HookParam *pHp, BYTE, DWORD* data, DWORD* split, DWORD* count)
					{
						uint64_t r10 = regof(r10, rsp_base);
						uint64_t r11 = regof(r11, rsp_base);
						if (r10==0x03FF || r11==0x03FF) {
							uint64_t rcx = regof(rcx, rsp_base);
							BYTE unicode = !(*(BYTE*)(rcx + 0x20) & 0x40); // [rcx+0x20) bit 0x40 == 0

							*data += unicode ? 0x48 : 0x30; //padding
							*count = ::strlen((char*)*data);
							if (!cpp_strnstr((char*)*data, "%", *count)) // not garbage
								return;
						}
						*count = 0;
					};
					hp.type = USING_STRING | NO_CONTEXT;
					hp.filter_fun = [](LPVOID data, DWORD *size, HookParam *, BYTE)
					{
						auto text = reinterpret_cast<LPSTR>(data);
						auto len = reinterpret_cast<size_t *>(size);

						if (text[0]!=0 && text[1]==0) {
							// text from unicode hook
							*len = text_buffer_length;
							::memmove(text, text_buffer, *len);
						}
						if (cpp_strnstr(text, "%", *len))
							return false;
						if (cpp_strnstr(text, "{", *len)) {
							StringCharReplacer(text, len, "{i}", 3, L'\'');
							StringCharReplacer(text, len, "{/i}", 4, L'\'');
							StringFilterBetween(text, len, "{", 1, "}", 1);
						}

						return true;
					};
					NewHook(hp, "Ren'py 3");

					return true;
				}
			}
		}
		ConsoleOutput("Textractor: Ren'py 3 failed: failed to find python3X.dll");
		return false;
	}
	bool UnsafeDetermineEngineType()
	{
		if (Util::CheckFile(L"PPSSPP*.exe") && FindPPSSPP()) return true;

		for (const wchar_t* moduleName : { (const wchar_t*)NULL, L"node.dll", L"nw.dll" }) if (InsertV8Hook(GetModuleHandleW(moduleName))) return true;

		if (GetModuleHandleW(L"GameAssembly.dll")) // TODO: is there a way to autofind hook?
		{
			ConsoleOutput("Textractor: Precompiled Unity found (searching for hooks should work)");
			wcscpy_s(spDefault.boundaryModule, L"GameAssembly.dll");
			spDefault.padding = 20;
			return true;
		}

		if (Util::CheckFile(L"*.py") && InsertRenpyHook() || InsertRenpy3Hook()) return true;

		for (const wchar_t* monoName : { L"mono.dll", L"mono-2.0-bdwgc.dll" }) if (HMODULE module = GetModuleHandleW(monoName)) if (InsertMonoHooks(module)) return true;

		for (std::wstring DXVersion : { L"d3dx9", L"d3dx10" })
			if (HMODULE module = GetModuleHandleW(DXVersion.c_str())) PcHooks::hookD3DXFunctions(module);
			else for (int i = 0; i < 50; ++i)
				if (HMODULE module = GetModuleHandleW((DXVersion + L"_" + std::to_wstring(i)).c_str())) PcHooks::hookD3DXFunctions(module);

		PcHooks::hookGDIFunctions();
		PcHooks::hookGDIPlusFunctions();
		return false;
	}
}
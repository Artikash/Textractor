// match.cc
// 8/9/2013 jichi
// Branch: ITH_Engine/engine.cpp, revision 133

#include "engine/match.h"
#include "engine/engine.h"
#include "engine/native/pchooks.h"
#include "util/util.h"
#include "main.h"
#include "ithsys/ithsys.h"

//#define ConsoleOutput(...)  (void)0     // jichi 8/18/2013: I don't need ConsoleOutput

enum { MAX_REL_ADDR = 0x200000 }; // jichi 8/18/2013: maximum relative address

// - Methods -

namespace Engine { 

	namespace {
		typedef wchar_t char16;

		typedef struct _cef_string_wide_t {
			wchar_t* str;
			size_t length;
			void (*dtor)(wchar_t* str);
		} cef_string_wide_t;

		typedef struct _cef_string_utf8_t {
			char* str;
			size_t length;
			void (*dtor)(char* str);
		} cef_string_utf8_t;

		typedef struct _cef_string_utf16_t {
			char16* str;
			size_t length;
			void (*dtor)(char16* str);
		} cef_string_utf16_t;
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

		#define retof(esp_base)         *(DWORD *)(esp_base) // return address
		#define regof(name, esp_base)   *(DWORD *)((esp_base) + pusha_##name##_off - 4)
		#define argof(count, esp_base)  *(DWORD *)((esp_base) + 4 * (count)) // starts from 1 instead of 0
		static void hook_cef_string_utf16_t(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
		{
			if (auto p = (_cef_string_utf16_t*)argof(1, esp_base)) {
				*data = (DWORD)p->str;
				*len = p->length; // for widechar

				auto s = regof(ecx, esp_base);
				for (int i = 0; i < 0x10; i++) // traverse pointers until a non-readable address is met
					if (s && !::IsBadReadPtr((LPCVOID)s, sizeof(DWORD)))
						s = *(DWORD*)s;
					else
						break;
				if (!s)
					s = hp->address;
				if (hp->type & USING_SPLIT) *split = s;
			}
		}
		static void hook_cef_string_wide_t(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
		{
			if (auto p = (_cef_string_wide_t*)argof(1, esp_base)) {
				*data = (DWORD)p->str;
				*len = p->length; // for widechar

				auto s = regof(ecx, esp_base);
				for (int i = 0; i < 0x10; i++) // traverse pointers until a non-readable address is met
					if (s && !::IsBadReadPtr((LPCVOID)s, sizeof(DWORD)))
						s = *(DWORD*)s;
					else
						break;
				if (!s)
					s = hp->address;
				if (hp->type & USING_SPLIT) *split = s;
			}
		}
		static void hook_cef_string_utf8_t(DWORD esp_base, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
		{
			if (auto p = (_cef_string_utf8_t*)argof(1, esp_base)) {
				*data = (DWORD)p->str;
				*len = p->length; // for widechar

				auto s = regof(ecx, esp_base);
				for (int i = 0; i < 0x10; i++) // traverse pointers until a non-readable address is met
					if (s && !::IsBadReadPtr((LPCVOID)s, sizeof(DWORD)))
						s = *(DWORD*)s;
					else
						break;
				if (!s)
					s = hp->address;
				if (hp->type & USING_SPLIT) *split = s;
			}
		}
		bool InsertlibcefHook(HMODULE module)
		{
			if (!module)return false;
			auto cef_string_ascii_to_utf16 = GetProcAddress(module, "cef_string_ascii_to_utf16");
			 
			bool ret = false;
			

			struct libcefFunction { // argument indices start from 0 for SpecialHookMonoString, otherwise 1
				const char* functionName;
				size_t textIndex; // argument index
				short lengthIndex; // argument index
				unsigned long hookType; // HookParam type
				void(*text_fun)(DWORD stack, HookParam* hp, BYTE obsoleteAlwaysZero, DWORD* data, DWORD* split, DWORD* len); // HookParam::text_fun_t
			};  

			HookParam hp = {};
			const libcefFunction funcs[] = {
				{"cef_string_utf8_set",1,0,USING_STRING | USING_UTF8 | NO_CONTEXT,NULL}, //ok
				{"cef_string_utf8_to_utf16",1,0,USING_STRING | USING_UTF8 | NO_CONTEXT,NULL},
				{"cef_string_utf8_to_wide",1,0,USING_STRING | USING_UTF8 | NO_CONTEXT,NULL}, //ok
				{"cef_string_utf8_clear",0,0,USING_STRING | USING_UTF8 | NO_CONTEXT,hook_cef_string_utf8_t}, 

				{"cef_string_utf16_set",1,0,USING_UNICODE | NO_CONTEXT,NULL}, //ok
				{"cef_string_utf16_clear",0,0,USING_UNICODE,hook_cef_string_utf16_t},//ok
				{"cef_string_utf16_to_utf8",1,0,USING_UNICODE | NO_CONTEXT,NULL},//ok
				{"cef_string_utf16_to_wide",1,0,USING_UNICODE | NO_CONTEXT,NULL},

				{"cef_string_ascii_to_utf16",1,0,USING_STRING | NO_CONTEXT,NULL},
				{"cef_string_ascii_to_wide",1,0,USING_STRING | NO_CONTEXT,NULL},

				{"cef_string_wide_set",1,0,USING_STRING | USING_UNICODE | NO_CONTEXT,NULL},//ok
				{"cef_string_wide_to_utf16",1,0,USING_STRING| USING_UNICODE | NO_CONTEXT,NULL},
				{"cef_string_wide_to_utf8",1,0,USING_STRING | USING_UNICODE | NO_CONTEXT,NULL}, 
				{"cef_string_wide_clear",0,0,USING_UNICODE,hook_cef_string_wide_t} 
			};
			for (auto func : funcs) {
				if (FARPROC addr = ::GetProcAddress(module, func.functionName)) {
					hp.address = (DWORD)addr;
					hp.type = func.hookType; 
					hp.offset = func.textIndex * 4;
					hp.length_offset = func.lengthIndex * 4;
					hp.text_fun = func.text_fun;
					ConsoleOutput("vnreng: libcef: INSERT");
					NewHook(hp, func.functionName);
					ret = true;
				}
			}

			if (!ret)
				ConsoleOutput("vnreng: Mono: failed to find function address");
			return ret;
			return false;
		}
	}

bool UnsafeDetermineEngineType()
{
	
	if (InsertlibcefHook(GetModuleHandleW(L"libcef.dll"))) {
		return true;
	}
	return false;
}

} // namespace Engine

// - API -

// EOF

// match.cc
// 8/9/2013 jichi
// Branch: ITH_Engine/engine.cpp, revision 133

#include "engine/match.h"
#include "engine/engine.h"
#include "engine/native/pchooks.h"
#include "util/util.h"
#include "main.h"
#include "ithsys/ithsys.h"
#include"memdbg/memsearch.h"
//#define ConsoleOutput(...)  (void)0     // jichi 8/18/2013: I don't need ConsoleOutput

enum { MAX_REL_ADDR = 0x200000 }; // jichi 8/18/2013: maximum relative address

// - Methods -

#define XX2 XX,XX       // WORD
#define XX4 XX2,XX2     // DWORD
#define XX8 XX4,XX4     // QWORD
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
		bool InsertHorkEye3Hook()
		{ 
			const BYTE bytes2[] =
			{ 
				0x55,
				0x8d,0xac,0x24,XX4, 
				0x81,0xec,XX4,
				0x6a,0xff,
				0x68,XX4,
				0x64,0xa1,0x00,0x00,0x00,0x00,
				0x50,
				0x83,0xec,0x38,   //必须是0x38，不能是XX，否则有重的。

//.text:0042E7F0 55                            push    ebp
//.text : 0042E7F1 8D AC 24 24 FF FF FF          lea     ebp,[esp - 0DCh]
//.text : 0042E7F8 81 EC DC 00 00 00             sub     esp, 0DCh
//.text : 0042E7FE 6A FF                         push    0FFFFFFFFh
//.text : 0042E800 68 51 1E 5C 00                push    offset SEH_42E7F0
//.text : 0042E805 64 A1 00 00 00 00             mov     eax, large fs : 0
//.text : 0042E80B 50                            push    eax
//.text : 0042E80C 83 EC 38                      sub     esp, 38h
//.text : 0042E80F A1 24 D0 64 00                mov     eax, ___security_cookie
//.text : 0042E814 33 C5 xor eax, ebp
//.text : 0042E816 89 85 D8 00 00 00             mov[ebp + 0DCh + var_4], eax
			};

			auto addr=MemDbg::findBytes(bytes2, sizeof(bytes2), processStartAddress, processStopAddress);
			 
			HookParam hp = {};
			hp.address = addr;
			hp.offset = 4;
			hp.type = USING_STRING;
			ConsoleOutput("Textractor: INSERT HorkEye3");
			NewHook(hp, "HorkEye3");
			return true;
			 

			ConsoleOutput("vnreng:HorkEye: pattern not found");
			return false;

		}
		 
		std::vector<DWORD> findrelativecall(const BYTE* pattern ,int length,DWORD calladdress,DWORD start, DWORD end)
		{
			std::vector<DWORD> save;
			for (; start < end;start+=1 ) { 
				DWORD addr=MemDbg::findBytes(pattern, length, start, end); 
				start = addr;
				if (!addr)return save;
				
				BYTE callop = 0xE8;
				
				union little {
					DWORD _dw;
					BYTE _bytes[4]; 
				}relative;
				relative._dw = (calladdress - addr -length- 5);
				DWORD calladdr = addr + length;
				if (*((BYTE*)calladdr) == callop) {

					calladdr += 1;
					BYTE* _b = (BYTE*)calladdr;
					BYTE* _a = relative._bytes;
					/*ConsoleOutput("%p", addr);
					ConsoleOutput("%p %x", calladdress, relative._dw);
					ConsoleOutput("%02x%02x%02x%02x %02x%02x%02x%02x", _a[0], _a[1], _a[2], _a[3], _b[0], _b[1], _b[2], _b[3]);*/
					if ((_a[0] == _b[0]) && (_a[1] == _b[1]) && (_a[2] == _b[2]) && (_a[3] == _b[3])) {
						save.push_back(start);
					}
				} 
			}
			return save;
		}
		DWORD reverseFindBytes(const BYTE* pattern, int length, DWORD start, DWORD end) {
			for (end -= length; end >= start; end -= 1) {
				 
				if (memcmp(pattern, (const BYTE*)(end), length) == 0) {
					return end;
				}
			}
		}
		bool InsertAGSHook()
		{
			 
			const BYTE bytes1[] = {
				/*.text:0043E3A0 55                            push    ebp
.text : 0043E3A1 8B EC                         mov     ebp, esp
.text : 0043E3A3 83 EC 38                      sub     esp, 38h
.text : 0043E3A6 53                            push    ebx
.text : 0043E3A7 56                            push    esi
.text : 0043E3A8 8B F1                         mov     esi, ecx*/
				0x55,
				0x8b,0xec,
				0x83,0xec,0x38,0x53,0x56,0x8b,0xf1
			};
			 
			ULONG addr = MemDbg::findBytes(bytes1, sizeof(bytes1), processStartAddress, processStopAddress); 
			if (!addr) { 
				return false;
			}  
			const BYTE bytes2[] = {
				/*	.text:0043E95E FF 75 08                      push[ebp + arg_0]
	.text:0043E961 8B CE                         mov     ecx, esi
	.text : 0043E963 E8 38 FA FF FF                call    sub_43E3A0*/
					0xff,0x75,0x08,
					0x8b,0xce
			};
			bool ok = false;
			  
			auto addrs = findrelativecall(bytes2, sizeof(bytes2), addr, processStartAddress, processStopAddress);
			const BYTE funcstart[] = {
				0x55,0x8b,0xec
			};
			for(auto addr :addrs){ 
				addr = reverseFindBytes(funcstart, sizeof(funcstart), addr-0x100, addr);
				if (!addr)continue; 
				HookParam hp = {};
				hp.address = addr;
				hp.offset = -8;
				hp.type = USING_STRING;
				ConsoleOutput("Textractor: INSERT HOOK_AGS %p",addr);
				NewHook(hp, "HOOK_AGS");
				ok = true;
			} 
			
			
			return ok;

		}

	}

bool UnsafeDetermineEngineType()
{
	if (Util::SearchResourceString(L"HorkEye")) { // appear in copyright: Copyright (C) HorkEye, http://horkeye.com
		InsertHorkEye3Hook();
		return true;
	}
	if (Util::CheckFile(L"voice/*.pk")|| Util::CheckFile(L"sound/*.pk")|| Util::CheckFile(L"misc/*.pk")) {
		if(InsertAGSHook())
			return true;
	}
	if (InsertlibcefHook(GetModuleHandleW(L"libcef.dll"))) {
		return true;
	}
	return false;
}

} // namespace Engine

// - API -

// EOF

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
namespace Engine{ 

	namespace Extra {
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
				ConsoleOutput("vnreng: libcef: failed to find function address");
			return ret;
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
			return 0;
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
		bool InsertWillPlusHook() {
			const BYTE bytes[] = {
				   0xc7,0x45,0xfc,0x00,0x00,0x00,0x00,
				   0x33,0xc9,
				   0xc7,0x47,0x78,0x00,0x00,0x00,0x00
			}; 
			ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), processStartAddress, processStopAddress);

			if (addr == 0)return false;

			addr = MemDbg::findEnclosingFunctionBeforeDword(0x83dc8b53, addr, MemDbg::MaximumFunctionSize, 1);

			if (addr == 0)return false;
			HookParam hp = {};
			hp.address = addr;
			hp.offset = 7*4;
			hp.type = USING_STRING|USING_UNICODE;
			ConsoleOutput("Textractor: INSERT WillPlus_extra");
			NewHook(hp, "WillPlus_extra");
			return  true;
		}
		bool InsertCsystemHook() {
			const BYTE bytes[] = {
				0x83,0xbe,XX4,0x00,
				0x8b,XX2,
				0x0f,0x85,XX4,
				0x83,0xbe,XX4,0x00,
				0x0f,0x85,XX4,
				0x83,0xbe,XX4,0x00,
				0x0f,0x84,XX4
/*.always:0048E4CA 83 BE F8 04 00 00 00          cmp     dword ptr[esi + 4F8h], 0
.always : 0048E4D1 8B 5D 84                      mov     ebx,[ebp + Src]
.always : 0048E4D4 0F 85 86 F8 FF FF             jnz     loc_48DD60
.always : 0048E4D4
.always : 0048E4DA 83 BE F4 04 00 00 00          cmp     dword ptr[esi + 4F4h], 0
.always : 0048E4E1 0F 85 79 F8 FF FF             jnz     loc_48DD60
.always : 0048E4E1
.always : 0048E4E7 83 BE 00 05 00 00 00          cmp     dword ptr[esi + 500h], 0
.always : 0048E4EE 0F 84 6C F8 FF FF             jz      loc_48DD60*/

			};
			const BYTE bytes2[] = {
				0x8b,0x86,XX4,
				0x6a,0x00,
				0x8b,0x80,XX4,
				0x50,
				0x8b,0x08,
				0xff,0x91,XX4,
				0x8b,0x45,XX,
				0x83,0xF8,0x08
				//
//.always:0048E51D 8B 86 58 0A 00 00             mov     eax,[esi + 0A58h]
//.always : 0048E523 6A 00                         push    0
//.always : 0048E525 8B 80 B8 01 00 00             mov     eax,[eax + 1B8h]
//.always : 0048E52B 50                            push    eax
//.always : 0048E52C 8B 08                         mov     ecx,[eax]
//.always:0048E52E FF 91 C4 00 00 00             call    dword ptr[ecx + 0C4h]
//.always : 0048E52E
//.always : 0048E534 8B 45 DC                      mov     eax,[ebp + var_24]
//.always : 0048E537 83 F8 08                      cmp     eax, 8
			};

			auto addrs = Util::SearchMemory(bytes, sizeof(bytes), PAGE_EXECUTE_READWRITE, processStartAddress, processStopAddress);
			auto addrs2 = Util::SearchMemory(bytes2, sizeof(bytes2), PAGE_EXECUTE_READWRITE, processStartAddress, processStopAddress);
			addrs.insert(addrs.end(), addrs2.begin(), addrs2.end());
			for (auto addr : addrs) { 
				HookParam hp = {};
				hp.address = addr;
				hp.offset = -0x14;
				hp.type = USING_STRING | USING_UNICODE | NO_CONTEXT;
				ConsoleOutput("Textractor: INSERT Csystem");
				NewHook(hp, "Csystem");
			}
			 
			
			return addrs.size()>0;
		}
		bool CheckCsystem() {
			//WendyBell
			wchar_t arcdatpattern[] = L"Arc0%d.dat";
			wchar_t arcdat[20];
			bool iswendybell = false;
			for (int i = 0; i < 10; i++) {
				wsprintf(arcdat, arcdatpattern, i);
				if (Util::CheckFile(arcdat)) {
					iswendybell = true; break;
				}
			}
			return (iswendybell && InsertCsystemHook());
		}
		

		bool Checkhibiki() {
			//ＬＯＶＥＬＹ×Ｃ∧ＴＩＯＮ
		/*seg000:0044FC05 83 FF 20                      cmp     edi, 20h ; ' '
seg000:0044FC08 0F 84 E6 00 00 00             jz      loc_44FCF4
seg000:0044FC08
seg000:0044FC0E 81 FF 00 30 00 00             cmp     edi, 3000h
seg000:0044FC14 0F 84 E9 00 00 00             jz      loc_44FD03*/
			const BYTE bytes[] = {
				   0x83,0xff,0x20,
				   0x0f,0x84,XX4,
				   0x81,0xff,0x00,0x30,0x00,0x00,
				   0x0f,0x84,XX4
			};

			auto addrs = Util::SearchMemory(bytes, sizeof(bytes), PAGE_EXECUTE, processStartAddress, processStopAddress);
			int bad = 0;
			for (auto addr :addrs) {
				addr = MemDbg::findEnclosingAlignedFunction(addr);
				if (!addr) { bad += 1; continue; }
				HookParam hp = {};
				hp.address =  addr;

				hp.offset = 12;
				hp.length_offset = 1;
				hp.type = USING_UNICODE;


				ConsoleOutput("Textractor: INSERT hibiki_extra %p",addr);
				
				NewHook(hp, "hibiki_extra"); 
			 }
				 
				
				
			return  addrs.size()>bad;

		}
		bool hookv8addr(HMODULE module) {
			auto [minAddress, maxAddress] = Util::QueryModuleLimits(module);
			const BYTE bytes[] = {
				0x89,0xc1,
				0x0f,0xb7,0xd8,
				0x81,0xe1,0x00,0xfc,0x00,0x00,
				0x81,0xf9,0x00,0xd8,0x00,0x00
// 下戸勇者
// .text:0162CE77 89 C1                         mov     ecx, eax
//.text : 0162CE79 0F B7 D8                      movzx   ebx, ax
//.text : 0162CE7C 81 E1 00 FC 00 00 and ecx, 0FC00h
//.text : 0162CE82 81 F9 00 D8 00 00             cmp     ecx, 0D800h
//.text : 0162CE88 74 56                         jz      short loc_162CEE0
//.text : 0162CE88
//.text : 0162CE8A 0F B7 C9                      movzx   ecx, cx
//.text : 0162CE8D 81 F9 00 DC 00 00             cmp     ecx, 0DC00h
//.text : 0162CE93 0F 84 43 03 00 00             jz      loc_162D1DC
//.text : 0162CE93
//.text : 0162CE99 8D 4B D0                      lea     ecx,[ebx - 30h]
//.text : 0162CE9C 83 F9 0A                      cmp     ecx, 0Ah
//.text : 0162CE9F 72 24                         jb      short loc_162CEC5; jumptable 0162CEBE cases 33,39 - 42,45,46,95
//.text:0162CE9F
//.text : 0162CEA1 89 D9                         mov     ecx, ebx
//.text : 0162CEA3 83 C9 20 or ecx, 20h
//.text : 0162CEA6 83 C1 9F                      add     ecx, 0FFFFFF9Fh
//.text : 0162CEA9 83 F9 1A                      cmp     ecx, 1Ah
//.text : 0162CEAC 72 17                         jb      short loc_162CEC5; jumptable 0162CEBE cases 33,39 - 42,45,46,95
//.text:0162CEAC
//.text : 0162CEAE 8D 4B DF                      lea     ecx,[ebx - 21h]; switch 63 cases
//.text:0162CEB1 66 83 F9 3E                   cmp     cx, 3Eh
//.text : 0162CEB5 0F 87 AD 01 00 00             ja      def_162CEBE; jumptable 0162CEBE default case
			};
			ULONG addr = MemDbg::findBytes(bytes, sizeof(bytes), minAddress, maxAddress);
			if (!addr) {
				return false;
			}
			HookParam hp = {};
			hp.address = addr;

			hp.offset =-8;

			hp.type = USING_UNICODE | NO_CONTEXT; 
			hp.length_offset = 1;
			ConsoleOutput("Textractor: INSERT extra_v8addr  %p", addr);

			NewHook(hp, "extra_v8addr");
			return true;
		}
		bool checkv8orcef() {
			for (HMODULE module : { (HMODULE)processStartAddress, GetModuleHandleW(L"node.dll"), GetModuleHandleW(L"nw.dll") })
				if (GetProcAddress(module, "?Write@String@v8@@QBEHPAGHHH@Z")) {
					bool ok1 = hookv8addr(module);
					if (ok1  )return true;
				}
			auto hm = GetModuleHandleW(L"libcef.dll");
			if (hm) {
				bool ok1 = hookv8addr(hm);
				bool ok2 = Extra::InsertlibcefHook(hm);
				if (ok1 || ok2)return true;
			}
			return false;
		}

	}

bool UnsafeDetermineEngineType_extra()
{
	if (Util::CheckFile(L"Rio.arc") && Util::CheckFile(L"Chip*.arc")) {
		Extra::InsertWillPlusHook();
		return true;
	}
	if (Extra::CheckCsystem()) {
		return true;
	}
	if (Util::SearchResourceString(L"HorkEye")) { // appear in copyright: Copyright (C) HorkEye, http://horkeye.com
		Extra::InsertHorkEye3Hook();
		return true;
	}
	if (Util::CheckFile(L"arc/*.dat") && Extra::Checkhibiki()) {
		return true;
	}
	if (Util::CheckFile(L"voice/*.pk")|| Util::CheckFile(L"sound/*.pk")|| Util::CheckFile(L"misc/*.pk")) {
		if(Extra::InsertAGSHook())
			return true;
	}

	if (Extra::checkv8orcef())return true;

	return false;
}

} // namespace Engine

// - API -

// EOF

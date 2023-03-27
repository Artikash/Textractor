#include "match.h"
#include "main.h"
#include "texthook.h"
#include "native/pchooks.h"
#include "mono/monoobject.h"
#include "mono/funcinfo.h"
#include "engine.h"
#include "util.h"

#define XX2 XX,XX       // WORD
#define XX4 XX2,XX2     // DWORD
#define XX8 XX4,XX4     // QWORD
namespace Engine
{ 
	 
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
	
	namespace Extra {
		bool InsertArtemis64Hook()
		{
			const BYTE BYTES[] = {
				0x48,0x89,0x5C,0x24,0x20,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xec,0x60
				//__int64 __fastcall sub_14017A760(__int64 a1, char *a2, char **a3)
				//FLIP FLOP IO
			};
			auto addrs = Util::SearchMemory(BYTES, sizeof(BYTES), PAGE_EXECUTE_READ, processStartAddress, processStopAddress);
			for (auto addr : addrs) {
				char info[1000] = {};
				sprintf(info, "Textractor: InsertArtemis64Hook %08x", addr);
				ConsoleOutput(info);
				HookParam hp = {};
				hp.address = addr;
				hp.type = USING_UTF8 | USING_STRING;
				hp.offset = -0x24 - 4;//rdx 
				NewHook(hp, "Artemis64");
				return true;
			}

			ConsoleOutput("Textractor: InsertArtemis64Hook failed");
			return false;
		}
		bool hookv8addr(HMODULE module) {
			auto [minAddress, maxAddress] = Util::QueryModuleLimits(module);
			bool ok = false;
			const BYTE bytes[] = {
				0x44,0x0f,0xb7,0xe8,
				0x89,0xc1,
				0x81,0xe1,0x00,0xfc,0x00,0x00,
				0x81,0xf9,0x00,0xd8,0x00,0x00
				//いもおか.exe
				// 该函数结构和下户勇者完全一样，但不知道为什么就是不读取。。
				//_QWORD *__fastcall sub_14150CF00(_QWORD *a1, _QWORD *a2, __int64 a3, char a4)
				//.text:000000014150D0CC 44 0F B7 E8                   movzx   r13d, ax
				//.text:000000014150D0D0 89 C1                         mov     ecx, eax
				//.text : 000000014150D0D2 81 E1 00 FC 00 00 and ecx, 0FC00h
				//.text : 000000014150D0D8 81 F9 00 D8 00 00             cmp     ecx, 0D800h
			};
			auto addrs = Util::SearchMemory(bytes, sizeof(bytes), PAGE_EXECUTE_READ, minAddress, maxAddress);
			for (auto addr : addrs) { 
				HookParam hp = {};
				hp.address = addr;

				hp.offset = -8;

				hp.type = USING_UNICODE | NO_CONTEXT;
				hp.length_offset = 1;
				ConsoleOutput("Textractor: INSERT extra_v8addr  %p", addr);

				NewHook(hp, "extra_v8addr");
				ok = true;
			}
			if(!ok)ConsoleOutput("extra_v8addr not found");
			return ok;
		}
		bool hookv8exports(HMODULE module) {
			ConsoleOutput("inter extra_v8orcef check");
			struct pairs_t {
				const BYTE* bytes;
				int size;
				int off;
			};
			auto [minAddress, maxAddress] = Util::QueryModuleLimits(module);
			bool ok = false;


			struct libcefFunction { // argument indices start from 0 for SpecialHookMonoString, otherwise 1
				const char* functionName;
				size_t textIndex; // argument index
				short lengthIndex; // argument index
				unsigned long hookType; // HookParam type
				void(*text_fun)(DWORD stack, HookParam* hp, BYTE obsoleteAlwaysZero, DWORD* data, DWORD* split, DWORD* len); // HookParam::text_fun_t
			};

			HookParam hp = {};
			enum {
				r8=-0x24-40 , //0x4c
				rdx=-0x24

			};
			const libcefFunction funcs[] = {
				{"?WriteUtf8@String@v8@@QEBAHPEAVIsolate@2@PEADHPEAHH@Z",r8,0,USING_STRING | USING_UTF8 | NO_CONTEXT,NULL}, //ok 
				{"?WriteUtf8@String@v8@@QEBAHPEADHPEAHH@Z",rdx,0,USING_STRING | USING_UTF8 | NO_CONTEXT,NULL}, //ok 
				{"?WriteOneByte@String@v8@@QEBAHPEAVIsolate@2@PEAEHHH@Z",r8,0,USING_STRING | USING_UTF8 | NO_CONTEXT,NULL}, //ok 
				{"?WriteOneByte@String@v8@@QEBAHPEAEHHH@Z",rdx,0,USING_STRING | USING_UTF8 | NO_CONTEXT,NULL}, //ok 
				{"?Write@String@v8@@QEBAHPEAVIsolate@2@PEAGHHH@Z",r8,0,USING_STRING | USING_UNICODE | NO_CONTEXT,NULL}, //ok 
				{"?Write@String@v8@@QEBAHPEAGHHH@Z",rdx,0,USING_STRING | USING_UNICODE | NO_CONTEXT,NULL}, //ok 
				{"?NewFromUtf8@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBDW4NewStringType@2@H@Z",r8,0,USING_STRING | USING_UTF8 | NO_CONTEXT,NULL}, //ok 
				{"?NewFromTwoByte@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBGW4NewStringType@2@H@Z",r8,0,USING_STRING | USING_UNICODE | NO_CONTEXT,NULL}, //ok 
				{"?NewFromOneByte@String@v8@@SA?AV?$MaybeLocal@VString@v8@@@2@PEAVIsolate@2@PEBEW4NewStringType@2@H@Z",r8,0,USING_STRING | USING_UTF8 | NO_CONTEXT,NULL}, //ok 
			};
			
			for (auto func : funcs) {
				if (FARPROC addr = ::GetProcAddress(module, func.functionName)) {
					hp.address = (uint64_t)addr ;
					hp.type = func.hookType;
					hp.offset = func.textIndex-4 ;
					hp.length_offset = func.lengthIndex * 4;
					hp.text_fun = func.text_fun;
					ConsoleOutput("vnreng: libcef: INSERT  %p", hp.address);
					NewHook(hp, "extra_v8exports");
					ok = true;
				}
			}
			 
			 
			if (!ok)ConsoleOutput("extra_v8exports not found");
			return ok;
		}
		bool checkv8orcef() {
			ConsoleOutput("checking v8cef");
			for (HMODULE module : { (HMODULE)processStartAddress, GetModuleHandleW(L"node.dll"), GetModuleHandleW(L"nw.dll") })
				if (GetProcAddress(module, "?Write@String@v8@@QEBAHPEAGHHH@Z")) {
					bool ok1 = hookv8addr(module);
					bool ok2= hookv8exports(module);
					if (ok1 || ok2)return true;
				}

			auto hm = GetModuleHandleW(L"libcef.dll");
			if (hm) {
				//todo
			}
			 
			return false;
		}
	}
	bool UnsafeDetermineEngineType()
	{ 
		if (Extra::checkv8orcef())return true;
		if (Util::CheckFile(L"*.pfs")) {
			Extra::InsertArtemis64Hook();
			return true;
		} 
		return false;
	}
}
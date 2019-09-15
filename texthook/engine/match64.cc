#include "match.h"
#include "main.h"
#include "texthook.h"
#include "native/pchooks.h"
#include "mono/monoobject.h"
#include "mono/funcinfo.h"
#include "engine.h"
#include "util.h"

namespace Engine
{
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
			const BYTE prolog1[] = { 0x55, 0x48, 0x8b, 0xec };
			const BYTE prolog2[] = { 0x48, 0x83, 0xec };
			for (auto [prolog, size] : Array<std::tuple<const BYTE*, size_t>>{ { prolog1, sizeof(prolog1) }, { prolog2, sizeof(prolog2) } })
			for (auto addr : Util::SearchMemory(prolog, size, PAGE_EXECUTE_READWRITE))
			{
				[](uint64_t addr)
				{
					__try
					{
						if (getJitInfo(domain, addr))
							if (char* name = getName(addr))
								if (strstr(name, "string:") && strstr(name, "+ 0x0") && !strstr(name, "string:mem"))
								{
									HookParam hp = {};
									hp.address = addr;
									hp.type = USING_STRING | USING_UNICODE | FULL_STRING;
									hp.offset = -0x20; // rcx
									hp.padding = 20;
									hp.length_fun = [](uintptr_t, uintptr_t data)
									{
										/* Artikash 6/18/2019:
										even though this should get the true length mono uses internally
										there's still some garbage picked up on https://vndb.org/v20403 demo, don't know why */
										int len = *(int*)(data - 4);
										return len > 0 && len < 1000 ? len * 2 : 0;
									};
									NewHook(hp, name);
								}
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {}
				}(addr);
			}
			return true;
		failed:
			ConsoleOutput("Textractor: Mono Dynamic failed");
			return true;
		};
		SetTrigger();
		return ret;
	}

	// Artikash 6/23/2019: V8 (JavaScript runtime) has rcx = string** at v8::String::Write
	// sample game https://www.freem.ne.jp/dl/win/18963
	bool InsertV8Hook(HMODULE module)
	{
		if (uint64_t addr = (uint64_t)GetProcAddress(module, "?Write@String@v8@@QEBAHPEAGHHH@Z"))
		{
			HookParam hp = {};
			hp.type = USING_STRING | USING_UNICODE | DATA_INDIRECT;
			hp.address = addr;
			hp.offset = -0x20; // rcx
			hp.index = 0;
			hp.padding = 23;
			hp.length_fun = [](uintptr_t, uintptr_t data)
			{
				int len = *(int*)(data - 4);
				return len > 0 && len < 1000 ? len * 2 : 0;
			};
			NewHook(hp, "JavaScript");
			return true;
		}
		return false;
	}

	bool UnsafeDetermineEngineType()
	{
		if (Util::CheckFile(L"PPSSPP*.exe") && FindPPSSPP()) return true;

		for (const wchar_t* moduleName : { (const wchar_t*)NULL, L"node.dll", L"nw.dll" }) if (InsertV8Hook(GetModuleHandleW(moduleName))) return true;

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
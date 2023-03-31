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
		//MonoImage* mono_assembly_get_image(MonoAssembly* assembly)：获取程序集的镜像。后面几乎所有的操作都会以MonoImage* 为第一个参数。
	static uintptr_t (*mono_assembly_get_image)(uintptr_t) = NULL;
	// const char* mono_image_get_name(MonoImage * image) :获取程序集名。我们用它判断哪个程序集是我们的目标
	static char* (*mono_image_get_name)(uintptr_t) = NULL;
	//MonoClass* mono_class_from_name (MonoImage *image, const char* name_space, const char *name):通过类名获取类(非实例)。
	static uintptr_t(*mono_class_from_name)(uintptr_t, char*, char*) = NULL;
	//MonoVTable* mono_class_vtable (MonoDomain *domain, MonoClass *klass)：获取vtable，我们通过它可以找到静态字段的起始地址。
	static uintptr_t(*mono_class_vtable)(uintptr_t, uintptr_t) = NULL;
	//void* mono_vtable_get_static_field_data (MonoVTable *vt)：获取静态字段的起始地址。
	static void*  (*mono_vtable_get_static_field_data)(uintptr_t) = NULL;
	//MonoMethod* mono_class_get_method_from_name (MonoClass *klass, const char *name, int param_count):获取方法(非native code地址)。
	//其中param_count是参数数量，可以输入-1来省略。此函数无法获取重载的方法，但对于我们来说足够了。
	static uintptr_t(*mono_class_get_method_from_name)(uintptr_t, char*,int) = NULL;
	//获取属性。用它可以进一步获得属性的getter和setter。
	//MonoProperty* mono_class_get_property_from_name(MonoClass* klass, const char* name)：
	static uintptr_t(*mono_class_get_property_from_name)(uintptr_t, char*) = NULL;
	//获取属性的getter和setter。
	//MonoMethod* mono_property_get_get_method(MonoProperty* prop) 与 MonoMethod* mono_property_get_set_method(MonoProperty* prop)：
	static uintptr_t(*mono_property_get_set_method)(uintptr_t) = NULL;
	// （不安全）返回方法的地址，如果方法尚未编译，则JIT开始编译。这个是解决问题的核心方法。 gpointer mono_compile_method (MonoMethod *method):
	static  uint64_t* (*mono_compile_method)(uintptr_t) = NULL;

	//获取函数的非托管块指针 (native)   gpointer mono_method_get_unmanaged_thunk (MonoMethod *method)
	//使用这个来获取native代码 方法尚未编译，会执行编译 并提取 x86版本可能使用的是__stdcall
	static  uint64_t* (*mono_method_get_unmanaged_thunk)(uintptr_t) = NULL;
	//MonoDomain* mono_get_root_domain (void) ：获取主作用域。用于附加线程以及获取静态字段的地址。
	static  MonoDomain* (*mono_get_root_domain)() = NULL;
	//void mono_thread_attach (MonoDomain*)：附加到进程的主线程。这个操作是必须的。
	static  void (*mono_thread_attach)(MonoDomain*) = NULL;

	//MonoAssembly* assembly，而后者则是void* user_data
	int getV8StringLength(uintptr_t stack, uintptr_t data) {
		int len = *(int*)(data - 4);
		int checkLength = len > 0 && len < PIPE_BUFFER_SIZE ? len : 0;
		//检查是否为错误的unicode字符
		for (size_t i = 0; i < checkLength; i++)
		{
			if (*(WORD*)(data + i * 2) == 0x0)
				return 0;
		}
		return checkLength * 2;

	}
	void MonoCallBack(uintptr_t assembly, void* userData) {
		uintptr_t mono_property = NULL;
		uintptr_t image=mono_assembly_get_image(assembly);
		// TMP_Text TextMeshProUGUI
	auto mono_tmp_class=mono_class_from_name(image, "TMPro", "TMP_Text");
	auto mono_ugui_class = mono_class_from_name(image, "UnityEngine.UI", "Text");
	auto mono_ngui_class = mono_class_from_name(image, "", "UILabel");
	if (!mono_tmp_class && !mono_ugui_class && !mono_ngui_class)
		return;
	if (mono_tmp_class) {
		mono_property = mono_class_get_property_from_name(mono_tmp_class, "text");
	}
	else if (mono_ugui_class)
	{
		mono_property = mono_class_get_property_from_name(mono_ugui_class, "text");
	}
	else if (mono_ngui_class) {
		mono_property = mono_class_get_property_from_name(mono_ngui_class, "text");
	}
				
	if (mono_property == NULL)
		return;
	auto mono_set_method= mono_property_get_set_method(mono_property);
	//注意必须调用mono_thread_attach 附加到主domain 才能调用 mono_method_get_unmanaged_thunk mono_compile_method 或mono_runtime_invoke
	mono_thread_attach(mono_get_root_domain());
	uint64_t* method_pointer= mono_compile_method(mono_set_method);
	if (method_pointer) {
		HookParam hp = {};
		hp.type = USING_STRING | USING_UNICODE;
		hp.address = (uint64_t)method_pointer;
		hp.offset = -0x28; // rdx
		//hp.index = 0;
		hp.padding = 0x14;
		if (mono_tmp_class) {
			ConsoleOutput("Mono_X64,Insert: TextMeshProUGUI_set_text Hook BY:IOV");
			hp.length_fun = getV8StringLength;
			NewHook(hp, "TextMeshProUGUI_set_text");
		}
		else if (mono_ugui_class)
		{
			ConsoleOutput("Mono_X64,Insert: UGUI_set_text Hook BY:IOV");
			hp.length_fun = getV8StringLength;
			NewHook(hp, "UGUI_set_text");
		}
		else if (mono_ngui_class)
		{
			ConsoleOutput("Mono_X64,Insert: NGUI_set_text Hook BY:IOV");
			hp.length_fun = getV8StringLength;
			NewHook(hp, "NGUI_set_text");
		}

	}
	
	}

	bool InsertMonoHooksByAssembly(HMODULE module) {
		//void mono_assembly_foreach (GFunc func, gpointer user_data)
		//遍历程序集。用于获取目标程序集的指针。其中的func 是一个回调函数，要自己写。它有两个参数，前者就是MonoAssembly*，而后者则是user_data
		static auto mono_assembly_foreach = (void (*)(void (*)(uintptr_t, void*), uintptr_t))GetProcAddress(module, "mono_assembly_foreach");
		mono_assembly_get_image= (uintptr_t(*)(uintptr_t))GetProcAddress(module, "mono_assembly_get_image");
		mono_image_get_name = (char* (*)(uintptr_t))GetProcAddress(module, "mono_image_get_name");
		mono_class_from_name = (uintptr_t(*)(uintptr_t, char*, char*))GetProcAddress(module, "mono_class_from_name");
		mono_class_get_property_from_name = (uintptr_t(*)(uintptr_t, char*))GetProcAddress(module, "mono_class_get_property_from_name");
		mono_property_get_set_method = (uintptr_t(*)(uintptr_t))GetProcAddress(module, "mono_property_get_set_method");
		mono_compile_method = (uint64_t * (*)(uintptr_t))GetProcAddress(module, "mono_compile_method");
		//mono_method_get_unmanaged_thunk= (uint64_t * (*)(uintptr_t))GetProcAddress(module, "mono_method_get_unmanaged_thunk");
		mono_get_root_domain = (MonoDomain * (*)())GetProcAddress(module, "mono_get_root_domain");
		
		mono_thread_attach = (void (*)(MonoDomain*))GetProcAddress(module, "mono_thread_attach");
		if (mono_assembly_foreach && mono_assembly_get_image && mono_image_get_name && mono_class_from_name &&
			mono_class_get_property_from_name && mono_property_get_set_method && mono_compile_method &&
			 mono_get_root_domain && mono_thread_attach) {
			mono_assembly_foreach(MonoCallBack, NULL);
			return true;
		}
		else
		{
			return false;
		}
	}	
	bool InsertMonoHooks(HMODULE module)
	{
		return InsertMonoHooksByAssembly(module);
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
			static auto getDomain = (MonoDomain * (*)())GetProcAddress(mono, "mono_domain_get");
			static auto getJitInfo = (MonoObject * (*)(MonoDomain*, uintptr_t))GetProcAddress(mono, "mono_jit_info_table_find");
			static auto getName = (char* (*)(uintptr_t))GetProcAddress(mono, "mono_pmip");
			if (!getDomain || !getName || !getJitInfo) goto failed;
			static auto domain = getDomain();
			if (!domain) goto failed;
			ConsoleOutput("Textractor: Mono Dynamic ENTER (hooks = %s)", loadedConfig ? loadedConfig : "brute force");
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
										if (!loadedConfig) hp.type |= KNOWN_UNSTABLE;
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

			if (!loadedConfig) ConsoleOutput("Textractor: Mono Dynamic used brute force: if performance issues arise, please specify the correct hook in the game configuration");
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
		auto getV8Length = [](uintptr_t, uintptr_t data)
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
					hp.address = (DWORD)GetProcAddress(module, "PyUnicodeUCS2_Format");
					if (!hp.address)
					{
						ConsoleOutput("Textractor: Ren'py failed: failed to find PyUnicodeUCS2_Format");
						return false;
					}
					hp.offset = -0x20; // rcx
					hp.index = 0x18;
					hp.length_offset = 0;
					//hp.split = pusha_ebx_off - 4;
					hp.type = USING_STRING | USING_UNICODE | NO_CONTEXT | DATA_INDIRECT /* | USING_SPLIT*/;
					//hp.filter_fun = [](void* str, auto, auto, auto) { return *(wchar_t*)str != L'%'; };
					NewHook(hp, "Ren'py");
					return true;
				}
			}
		}
		ConsoleOutput("Textractor: Ren'py failed: failed to find python2X.dll");
		return false;
	}
	int getGodoStringLength(uintptr_t stack, uintptr_t data) {
		int len = *(int*)(data - 4);
		len--;
		int checkLength = len > 0 && len < PIPE_BUFFER_SIZE ? len : 0;
		//检查是否为错误的unicode字符
		for (size_t i = 0; i < checkLength; i++)
		{
			if (*(WORD*)(data + i * 2) == 0x0)
				return 0;
		}
		return checkLength * 2;

	}
	//BY:IOV
	bool InsertGodotHook_X64() {
		const BYTE bytes[] = { 0x8B,0x40,0xFC,0x83,0xF8,0x01,0x83,0xD0,0xFF,0x41,0x39,0xC6 };

		ULONG64 range = min(processStopAddress - processStartAddress, X64_MAX_REL_ADDR);
		for (auto addr : Util::SearchMemory(bytes, sizeof(bytes), PAGE_EXECUTE, processStartAddress, processStartAddress + range)) {
			HookParam myhp = {};
			myhp.address = addr;

			myhp.type = USING_STRING | USING_UNICODE | NO_CONTEXT; // /HQ 不使用上下文区分 把所有线程的文本都提取
			//myhp.padding = 0xc;//[esp+4]+padding
			// data_offset
			myhp.offset = -0xC-4;//RCX
			myhp.length_fun = getGodoStringLength;
			char nameForUser[HOOK_NAME_SIZE] = "RichTextLabel_add_text";
			NewHook(myhp, nameForUser);
			ConsoleOutput("Insert: Godot_add_text_X64 Hook ");
			return true;
		}

		ConsoleOutput("vnreng:Godot_x64: pattern not found");
		return false;
	}
	bool UnsafeDetermineEngineType()
	{
		if (Util::CheckFile(L"PPSSPP*.exe") && FindPPSSPP()) return true;
		
		if (Util::CheckFile(L"*.pck")) {
			return InsertGodotHook_X64();			 
		}
	
		for (const wchar_t* moduleName : { (const wchar_t*)NULL, L"node.dll", L"nw.dll" }) if (InsertV8Hook(GetModuleHandleW(moduleName))) return true;

		if (GetModuleHandleW(L"GameAssembly.dll")) // TODO: is there a way to autofind hook?
		{
			ConsoleOutput("Textractor: Precompiled Unity found (searching for hooks should work)");
			wcscpy_s(spDefault.boundaryModule, L"GameAssembly.dll");
			spDefault.padding = 20;
			return true;
		}

		if (Util::CheckFile(L"*.py") && InsertRenpyHook()) return true;

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

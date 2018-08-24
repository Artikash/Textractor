// main.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/main.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "main.h"
#include "defs.h"
#include "engine/engine.h"
#include "engine/match.h"
#include "hijack/texthook.h"
#include "util/growl.h"

// Global variables

// jichi 6/3/2014: memory range of the current module
DWORD processStartAddress,
processStopAddress;

WCHAR hm_section[0x100];
HANDLE hSection;
bool running;
int currentHook = 0,
user_hook_count = 0;
DWORD trigger = 0;
HANDLE
hFile,
hMutex,
hmMutex;

void CreatePipe();

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD fdwReason, LPVOID unused)
{
	switch (fdwReason) 
	{
	case DLL_PROCESS_ATTACH:
	{
		::hmMutex = CreateMutexW(nullptr, FALSE, (ITH_HOOKMAN_MUTEX_ + std::to_wstring(GetCurrentProcessId())).c_str());
		if (GetLastError() == ERROR_ALREADY_EXISTS) return FALSE;
		DisableThreadLibraryCalls(hModule);

		// jichi 9/25/2013: Interprocedural communication with vnrsrv.
		hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, HOOK_SECTION_SIZE, (ITH_SECTION_ + std::to_wstring(GetCurrentProcessId())).c_str());
		::hookman = (TextHook*)MapViewOfFile(hSection, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, HOOK_BUFFER_SIZE);

		::processStartAddress = ::processStopAddress = (DWORD)GetModuleHandleW(nullptr);

		MEMORY_BASIC_INFORMATION info;
		do
		{
			VirtualQuery((void*)::processStopAddress, &info, sizeof(info));
			::processStopAddress = (DWORD)info.BaseAddress + info.RegionSize;
		} while (info.Protect > PAGE_NOACCESS);
		processStopAddress -= info.RegionSize;

		::running = true;
		::current_available = ::hookman;

		CreatePipe();
	} 
	break;
	case DLL_PROCESS_DETACH:
	{
		::running = false;

		for (TextHook *man = ::hookman; man < ::hookman + MAX_HOOK; man++) if (man->Address()) man->ClearHook();
		//if (ith_has_section)
		UnmapViewOfFile(::hookman);

		CloseHandle(::hookPipe);
		CloseHandle(hSection);
		CloseHandle(hMutex);
		CloseHandle(hmMutex);
		//} ITH_EXCEPT {}
	}
	break;
	}
	return TRUE;
}

//extern "C" {
DWORD NewHook(const HookParam &hp, LPCSTR lpname, DWORD flag)
{
	std::string name = lpname;
	int current = ::current_available - ::hookman;
	if (current < MAX_HOOK) {
		//flag &= 0xffff;
		//if ((flag & HOOK_AUXILIARY) == 0)
		flag |= HOOK_ADDITIONAL;
		if (name[0] == '\0')
		{
			name = "UserHook" + std::to_string(user_hook_count++);
		}

		ConsoleOutput(("vnrcli:NewHook: try inserting hook: " + name).c_str());

		// jichi 7/13/2014: This function would raise when too many hooks added
		::hookman[current].InitHook(hp, name.c_str(), flag & 0xffff);

		if (::hookman[current].InsertHook() == 0) {
			ConsoleOutput(("vnrcli:NewHook: inserted hook: " + name).c_str());
			NotifyHookInsert(hp, name.c_str());
		}
		else
			ConsoleOutput("vnrcli:NewHook:WARNING: failed to insert hook");
	}
	return 0;
}
DWORD RemoveHook(unsigned __int64 addr)
{
	for (int i = 0; i < MAX_HOOK; i++)
		if (::hookman[i].Address() == addr) {
			::hookman[i].ClearHook();
			return 0;
		}
	return 0;
}

DWORD SwitchTrigger(DWORD t)
{
	trigger = t;
	return 0;
}

// EOF
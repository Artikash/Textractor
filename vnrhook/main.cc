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
#include "MinHook.h"
#include "pipe.h"
#include "engine/engine.h"
#include "engine/match.h"
#include "hijack/texthook.h"
#include "util/growl.h"

HANDLE hSection;
bool running;
int currentHook = 0, userhookCount = 0;
DWORD trigger = 0;
HANDLE hmMutex;

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
		memset(::hookman, 0, HOOK_BUFFER_SIZE);

		MH_Initialize();

		::running = true;

		CreatePipe();
	} 
	break;
	case DLL_PROCESS_DETACH:
	{
		::running = false;
		MH_Uninitialize();
		for (TextHook *man = ::hookman; man < ::hookman + MAX_HOOK; man++) if (man->hp.address) man->ClearHook();
		//if (ith_has_section)
		UnmapViewOfFile(::hookman);

		CloseHandle(::hookPipe);
		CloseHandle(hSection);
		CloseHandle(hmMutex);
		//} ITH_EXCEPT {}
	}
	break;
	}
	return TRUE;
}

//extern "C" {
void NewHook(const HookParam &hp, LPCSTR lpname, DWORD flag)
{
	std::string name = lpname;
	if (++currentHook < MAX_HOOK) 
	{
		if (name[0] == '\0') name = "UserHook" + std::to_string(userhookCount++);
		ConsoleOutput(("NextHooker: try inserting hook: " + name).c_str());

		// jichi 7/13/2014: This function would raise when too many hooks added
		::hookman[currentHook].InitHook(hp, name.c_str(), flag);
		if (::hookman[currentHook].InsertHook()) ConsoleOutput(("NextHooker: inserted hook: " + name).c_str());
		else ConsoleOutput("NextHooker:WARNING: failed to insert hook");
	}
	else ConsoleOutput("NextHooker: too many hooks: can't insert");
}

void RemoveHook(uint64_t addr)
{
	for (int i = 0; i < MAX_HOOK; i++)
		if (abs((long long)(::hookman[i].hp.address - addr)) < 9)
		{
			::hookman[i].ClearHook();
			return;
		}
}

void SwitchTrigger(DWORD t)
{
	trigger = t;
}

// EOF
// main.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/main.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "main.h"
#include "hijack/texthook.h"
#include "include/defs.h"

// Global variables

// jichi 6/3/2014: memory range of the current module
DWORD processStartAddress,
      processStopAddress;

enum { HOOK_BUFFER_SIZE = MAX_HOOK * sizeof(TextHook) };
//#define MAX_HOOK (HOOK_BUFFER_SIZE/sizeof(TextHook))
DWORD hook_buff_len = HOOK_BUFFER_SIZE;

WCHAR hm_section[0x100];
HANDLE hSection;
bool running;
int currentHook = 0,
    user_hook_count = 0;
HANDLE
    hFile,
    hMutex,
    hmMutex;
HMODULE currentModule;

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD fdwReason, LPVOID unused)
{
	static HANDLE pipeThread;


  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    {
      static bool attached_ = false;
	  if (attached_) // already attached
	  {
		  return TRUE;
	  }        
      attached_ = true;

      DisableThreadLibraryCalls(hModule);

      swprintf(hm_section, ITH_SECTION_ L"%d", GetCurrentProcessId());

      // jichi 9/25/2013: Interprocedural communication with vnrsrv.
	  hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, HOOK_SECTION_SIZE, hm_section);
	  ::hookman = nullptr;
	  // Artikash 6/20/2018: This crashes certain games (https://vndb.org/v7738). No idea why.
      ::hookman = (TextHook*)MapViewOfFile(hSection, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, HOOK_SECTION_SIZE / 2);

	  ::processStartAddress = (DWORD)GetModuleHandleW(nullptr);

      {
        wchar_t hm_mutex[0x100];
        swprintf(hm_mutex, ITH_HOOKMAN_MUTEX_ L"%d", GetCurrentProcessId());
		::hmMutex = CreateMutexW(nullptr, FALSE, hm_mutex);
      }
      {
        wchar_t dll_mutex[0x100];
        swprintf(dll_mutex, ITH_PROCESS_MUTEX_ L"%d", GetCurrentProcessId());
        DWORD exists;
		::hMutex = CreateMutexW(nullptr, TRUE, dll_mutex); // jichi 9/18/2013: own is true, make sure the injected dll is singleton
        if (GetLastError() == ERROR_ALREADY_EXISTS)
          return FALSE;
      }

      ::running = true;
      ::current_available = ::hookman;
	  ::currentModule = hModule;

      pipeThread = CreateThread(nullptr, 0, PipeManager, 0, 0, nullptr);
    } break;
  case DLL_PROCESS_DETACH:
    {
      static bool detached_ = false;
      if (detached_) // already detached
        return TRUE;
      detached_ = true;

      // jichi 10/2/2103: Cannot use __try in functions that require object unwinding
      //ITH_TRY {
      ::running = false;

      if (pipeThread) {
		  WaitForSingleObject(pipeThread, TIMEOUT);
        CloseHandle(pipeThread);
      }

      for (TextHook *man = ::hookman; man < ::hookman + MAX_HOOK; man++)
        man->ClearHook();
      //if (ith_has_section)
	  UnmapViewOfFile(::hookman);

      CloseHandle(hSection);
      CloseHandle(hMutex);
      CloseHandle(hmMutex);
      //} ITH_EXCEPT {}
    } break;
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
    } else
      ConsoleOutput("vnrcli:NewHook:WARNING: failed to insert hook");
  }
  return 0;
}
DWORD RemoveHook(DWORD addr)
{
  for (int i = 0; i < MAX_HOOK; i++)
    if (::hookman[i].Address ()== addr) {
      ::hookman[i].ClearHook();
      return 0;
    }
  return 0;
}

// EOF
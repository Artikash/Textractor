// main.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/main.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "src/main.h"
#include "src/engine/engine.h"
#include "src/engine/match.h"
#include "src/hijack/texthook.h"
#include "src/util/growl.h"
#include "src/except.h"
#include "include/const.h"
#include "include/defs.h"
#include "ithsys/ithsys.h"
#include "util/util.h"
#include <cstdio> // for swprintf
//#include "ntinspect/ntinspect.h"
//#include "winseh/winseh.h"
//#include <boost/foreach.hpp>
//#include "md5.h"
//#include <ITH\AVL.h>
//#include <ITH\ntdll.h>

// Global variables

// jichi 6/3/2014: memory range of the current module
DWORD processStartAddress,
      processStopAddress;

enum { HOOK_BUFFER_SIZE = MAX_HOOK * sizeof(TextHook) };
//#define MAX_HOOK (HOOK_BUFFER_SIZE/sizeof(TextHook))
DWORD hook_buff_len = HOOK_BUFFER_SIZE;

namespace { FilterRange _filter[IHF_FILTER_CAPACITY]; }
FilterRange *filter = _filter;

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
HMODULE currentModule;
//DWORD current_process_id;
extern DWORD enter_count;
//extern LPWSTR current_dir;
extern DWORD engine_type;

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
	  NtMapViewOfSection(hSection, NtCurrentProcess(),
		  (LPVOID *)&::hookman, 0, hook_buff_len, 0, &hook_buff_len, ViewUnmap, 0,
		  PAGE_EXECUTE_READWRITE);
	  // Artikash 6/20/2018: This crashes certain games (https://vndb.org/v7738). No idea why.
      //::hookman = (TextHook*)MapViewOfFile(hSection, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, HOOK_SECTION_SIZE / 2);

	  ::processStartAddress = (DWORD)GetModuleHandleW(nullptr);

	  // Artikash 7/1/2018: No idea how the everliving fuck this works, but it finds the process stop address.
	  PROCESS_BASIC_INFORMATION info;
	  NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &info, sizeof(PROCESS_BASIC_INFORMATION), 0);
	  ::processStopAddress = ::processStartAddress + ((LDR_DATA_TABLE_ENTRY*)&info.PebBaseAddress->Ldr->InLoadOrderModuleList.Flink->Flink)->SizeOfImage;

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

      Engine::terminate();

      if (pipeThread) {
		  WaitForSingleObject(pipeThread, TIMEOUT);
        CloseHandle(pipeThread);
      }

      for (TextHook *man = ::hookman; man->RemoveHook(); man++);
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
DWORD NewHook(const HookParam &hp, LPCSTR name, DWORD flag)
{
  CHAR str[128];
  int current = ::current_available - ::hookman;
  if (current < MAX_HOOK) {
    //flag &= 0xffff;
    //if ((flag & HOOK_AUXILIARY) == 0)
    flag |= HOOK_ADDITIONAL;
	if (name == NULL || name[0] == '\0')
	{
		sprintf(str, "UserHook%d", user_hook_count++);
	}
	else
	{
		strcpy(str, name);
	}

    ConsoleOutput("vnrcli:NewHook: try inserting hook:");
	ConsoleOutput(str);

    // jichi 7/13/2014: This function would raise when too many hooks added
    ::hookman[current].InitHook(hp, str, flag & 0xffff);

    if (::hookman[current].InsertHook() == 0) {
      ConsoleOutput("vnrcli:NewHook: hook inserted");
	  NotifyHookInsert(hp, name);
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

DWORD SwitchTrigger(DWORD t)
{
  trigger = t;
  return 0;
}

// EOF
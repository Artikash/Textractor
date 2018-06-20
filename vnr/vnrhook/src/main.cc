// main.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/main.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "src/main.h"
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
bool running,
     live = false;
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
std::unordered_map<std::string, FunctionInfo> functionInfoByName;

namespace { // unnamed

void AddModule(DWORD hModule, DWORD size, LPWSTR name)
{
  FunctionInfo info = {0, hModule, size, name};
  IMAGE_DOS_HEADER *DosHdr = (IMAGE_DOS_HEADER *)hModule;
  if (IMAGE_DOS_SIGNATURE == DosHdr->e_magic) {
    DWORD dwReadAddr = hModule + DosHdr->e_lfanew;
    IMAGE_NT_HEADERS *NtHdr = (IMAGE_NT_HEADERS *)dwReadAddr;
    if (IMAGE_NT_SIGNATURE == NtHdr->Signature) {
      DWORD dwExportAddr = NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      if (dwExportAddr == 0)
        return;
      dwExportAddr += hModule;
      IMAGE_EXPORT_DIRECTORY *ExtDir = (IMAGE_EXPORT_DIRECTORY*)dwExportAddr;
      dwExportAddr = hModule+ExtDir->AddressOfNames;
      for (UINT uj = 0; uj < ExtDir->NumberOfNames; uj++) {
        DWORD dwFuncName = *(DWORD *)dwExportAddr;
        char *pcBuffer = (char *)(hModule + dwFuncName);
        char *pcFuncPtr = (char *)(hModule + (DWORD)ExtDir->AddressOfNameOrdinals+(uj * sizeof(WORD)));
        WORD word = *(WORD *)pcFuncPtr;
        pcFuncPtr = (char *)(hModule + (DWORD)ExtDir->AddressOfFunctions+(word * sizeof(DWORD)));
        info.addr = hModule + *(DWORD *)pcFuncPtr;
		::functionInfoByName[std::string(pcBuffer)] = info;
        dwExportAddr += sizeof(DWORD);
      }
    }
  }
}

void AddAllModules()
{
  // jichi 9/26/2013: AVLTree is already zero
  PPEB ppeb;
  __asm {
    mov eax, fs:[0x30]
    mov ppeb, eax
  }
  DWORD temp = *(DWORD *)(&ppeb->Ldr->InLoadOrderModuleList);
  PLDR_DATA_TABLE_ENTRY it = (PLDR_DATA_TABLE_ENTRY)temp;
  while (it->SizeOfImage) {
    AddModule((DWORD)it->DllBase, it->SizeOfImage, it->BaseDllName.Buffer);
    it = (PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink;
    if (*(DWORD *)it == temp)
      break;
  }
}

} // unnamed namespace

DWORD GetFunctionAddr(const char *name, DWORD *addr, DWORD *base, DWORD *size, LPWSTR *base_name)
{
	if (::functionInfoByName.find(std::string(name)) == ::functionInfoByName.end())
		return FALSE;
	FunctionInfo functionInfo = ::functionInfoByName[std::string(name)];
	if (addr) *addr = functionInfo.addr;
	if (base) *base = functionInfo.module;
	if (size) *size = functionInfo.size;
	return TRUE;
}

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
      AddAllModules();
	  ::currentModule = hModule;

      pipeThread = CreateRemoteThread(GetCurrentProcess(), nullptr, 0, PipeManager, 0, 0, nullptr);
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
      ::live = false;

      Engine::terminate();

      if (pipeThread) {
		  WaitForSingleObject(pipeThread, TIMEOUT);
        CloseHandle(pipeThread);
      }

      for (TextHook *man = ::hookman; man->RemoveHook(); man++);
      //LARGE_INTEGER lint = {-10000, -1};
      while (::enter_count)
        Sleep(1); // jichi 9/28/2013: sleep for 1 ms
        //NtDelayExecution(0, &lint);
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

    ConsoleOutput("vnrcli:NewHook: try inserting hook");

    // jichi 7/13/2014: This function would raise when too many hooks added
    ::hookman[current].InitHook(hp, str, flag & 0xffff);

    if (::hookman[current].InsertHook() == 0) {
      ConsoleOutput("vnrcli:NewHook: hook inserted");
      //ConsoleOutputW(name);
      //swprintf(str,L"Insert address 0x%.8X.", hookman[current].Address());
	  NotifyHookInsert(0);
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
// hookman.cc
// 8/24/2013 jichi
// Branch IHF/HookManager.cpp, rev 133
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
# pragma warning (disable:4146)   // C4146: unary minus operator applied to unsigned type
#endif // _MSC_VER

#include "hookman.h"
#include "vnrhook/include/const.h"
#include "vnrhook/include/defs.h"
#include "vnrhook/include/types.h"
#include "ithsys/ithsys.h"
#include <stdio.h>
//#include <emmintrin.h>
#include "profile/Profile.h"
#include "profile/pugixml.h"
#include "profile/misc.h"

#define DEBUG "vnrhost/hookman.cc"

namespace { // unnamed
//enum { MAX_ENTRY = 0x40 };

#define HM_LOCK CriticalSectionLocker d_locker(hmcs) // Synchronized scope for accessing private data


} // unnamed namespace

HookManager *man; // jichi 9/22/2013: initialized in main
//BitMap* pid_map;
DWORD clipboard_flag,
      split_time,
      repeat_count,
      global_filter,
      cyclic_remove;

DWORD GetHookName(LPSTR str, DWORD pid, DWORD hook_addr, DWORD max)
{
  if (!pid)
    return 0;

  DWORD len = 0;
  max--; //for '\0' magic marker.

  //if (pid == 0) {
  //  len = wcslen(HookNameInitTable[0]);
  //  if (len >= max)
  //    len = max;
  //  memcpy(str, HookNameInitTable[0], len << 1);
  //  str[len] = 0;
  //  return len;
  //}

  //::man->LockProcessHookman(pid);
  ProcessRecord *pr = ::man->GetProcessRecord(pid);
  if (!pr)
    return 0;
  WaitForSingleObject(pr->hookman_mutex, 0);
  const Hook *hks = (const Hook *)pr->hookman_map;
  for (int i = 0; i < MAX_HOOK; i++)
    if (hks[i].Address() == hook_addr) {
      len = hks[i].NameLength();
      if (len >= max)
        len = max;
      ReadProcessMemory(pr->process_handle, hks[i].Name(), str, len, &len);
      if (str[len - 1] == 0)
        len--;
      else
        str[len] = 0;
      break;
    }

  ReleaseMutex(pr->hookman_mutex);
  //::man->UnlockProcessHookman(pid);
  return len;
}

//Class member of HookManger
HookManager::HookManager() :
	// jichi 9/21/2013: Zero memory
	//CRITICAL_SECTION hmcs;
	current(nullptr)
	, create(nullptr)
	, remove(nullptr)
	, reset(nullptr)
	, attach(nullptr)
	, detach(nullptr)
	, hook(nullptr)
	, new_thread_number(0)
	, threadTable()
	, processRecordsByIds()
{
	TextThread* consoleTextThread = threadTable[{0, -1UL, -1UL, -1UL}] = new TextThread({ 0, -1UL, -1UL, -1UL }, new_thread_number++);
  consoleTextThread->Status() |= USING_UNICODE;
  SetCurrent(consoleTextThread);

  InitializeCriticalSection(&hmcs);
}

HookManager::~HookManager()
{
	// Artikash 5/31/2018: This is called when the program terminates, so Windows should automatically free all these resources.....right?
  //LeaveCriticalSection(&hmcs);
  //LARGE_INTEGER timeout={-1000*1000,-1};
  //IthBreak();
  //NtWaitForSingleObject(destroy_event, 0, 0);
  //CloseHandle(destroy_event);
  //CloseHandle(cmd_pipes[0]);
  //CloseHandle(recv_threads[0]);
  //delete thread_table;
  //delete head.key;
  //DeleteCriticalSection(&hmcs);
}

TextThread *HookManager::FindSingle(DWORD number)
{ 
	for (auto i : threadTable)
	{
		if (i.second->Number() == number)
		{
			return i.second;
		}
	}
	return nullptr;
}

void HookManager::SetCurrent(TextThread *it)
{
  if (current)
    current->Status() &= ~CURRENT_SELECT;
  current = it;
  if (it)
    it->Status() |= CURRENT_SELECT;
}
void HookManager::SelectCurrent(DWORD num)
{
  if (TextThread *st = FindSingle(num)) {
    SetCurrent(st);
    if (reset)
      reset(st);
    //st->ResetEditText();
  }
}
void HookManager::RemoveSingleHook(DWORD pid, DWORD addr)
{
  HM_LOCK;
  std::vector<ThreadParameter> removedThreads;
  for (auto i : threadTable)
  {
	  if (i.second->PID() == pid && i.second->Addr() == addr)
	  {
		  if (remove)
		  {
			  remove(i.second);
		  }
		  delete i.second;
		  removedThreads.push_back(i.first);
	  }
  }
  for (auto i : removedThreads)
  {
	  threadTable.erase(i);
  }
  SelectCurrent(0);
}

void HookManager::RemoveProcessContext(DWORD pid)
{
	HM_LOCK;
	std::vector<ThreadParameter> removedThreads;
	for (auto i : threadTable)
	{
		if (i.second->PID() == pid)
		{
			if (remove)
			{
				remove(i.second);
			}
			delete i.second;
			removedThreads.push_back(i.first);
		}
	}
	for (auto i : removedThreads)
	{
		threadTable.erase(i);
	}
	SelectCurrent(0);
}

void HookManager::RegisterProcess(DWORD pid, HANDLE hostPipe)
{
  HM_LOCK;

  ProcessRecord* record = processRecordsByIds[pid] = new ProcessRecord;
  record->hostPipe = hostPipe;
  record->hookman_section = OpenFileMappingW(FILE_MAP_READ, FALSE, (ITH_SECTION_ + std::to_wstring(pid)).c_str());
  record->hookman_map = MapViewOfFile(record->hookman_section, FILE_MAP_READ, 0, 0, HOOK_SECTION_SIZE / 2); // jichi 1/16/2015: Changed to half to hook section size
  record->process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  record->hookman_mutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, (ITH_HOOKMAN_MUTEX_ + std::to_wstring(pid)).c_str());

  if (attach)
    attach(pid);

}

void HookManager::UnRegisterProcess(DWORD pid)
{
  HM_LOCK;

  ProcessRecord pr = *processRecordsByIds[pid];
  CloseHandle(pr.hookman_mutex);
  UnmapViewOfFile(pr.hookman_map);
  CloseHandle(pr.process_handle);
  CloseHandle(pr.hookman_section);
  processRecordsByIds.erase(pid);
    RemoveProcessContext(pid);
  
  if (detach)
    detach(pid);
}

void HookManager::DispatchText(DWORD pid, const BYTE *text, DWORD hook, DWORD retn, DWORD spl, int len)
{
  // jichi 20/27/2013: When PID is zero, the text comes from console, which I don't need
  if (!text || !pid || len <= 0)
    return;
  HM_LOCK;
  ThreadParameter tp = {pid, hook, retn, spl};
  TextThread *it;
  if (!(it = threadTable[tp]))
  {
	  it = threadTable[tp] = new TextThread(tp, new_thread_number++);
	  if (create)
	  {
		  create(it);
	  }
  }
  it->AddText(text, len);
}

void HookManager::AddConsoleOutput(LPCWSTR text)
{
  if (text) 
  {
    int len = wcslen(text) * 2;
	TextThread *console = threadTable[{0, -1UL, -1UL, -1UL}];
    console->AddSentence(std::wstring(text));
  }
}

void HookManager::ClearCurrent()
{
  HM_LOCK;
  if (current) {
    current->Reset();
    if (reset)
      reset(current);
  }
}

ProcessRecord *HookManager::GetProcessRecord(DWORD pid)
{
  HM_LOCK;
  return processRecordsByIds[pid];
}

HANDLE HookManager::GetCommandPipe(DWORD pid)
{
  HM_LOCK;
  return processRecordsByIds[pid] ? processRecordsByIds[pid]->hostPipe : nullptr;
}

MK_BASIC_TYPE(DWORD)
MK_BASIC_TYPE(LPVOID)

void AddHooksToProfile(Profile& pf, const ProcessRecord& pr);
DWORD AddThreadToProfile(Profile& pf, const ProcessRecord& pr, TextThread* thread);
void MakeHookRelative(const ProcessRecord& pr, HookParam& hp);

void HookManager::GetProfile(DWORD pid, pugi::xml_node profile_node)
{
	const ProcessRecord* pr = GetProcessRecord(pid);
	if (pr == NULL)
		return;
	Profile pf(L"serialize");
	AddHooksToProfile(pf, *pr);
	AddThreadsToProfile(pf, *pr, pid);
	pf.XmlWriteProfile(profile_node);
}

void AddHooksToProfile(Profile& pf, const ProcessRecord& pr)
{
	WaitForSingleObject(pr.hookman_mutex, 0);
	auto hooks = (const Hook*)pr.hookman_map;
	for (DWORD i = 0; i < MAX_HOOK; ++i)
	{
		if (hooks[i].Address() == 0)
			continue;
		auto& hook = hooks[i];
		DWORD type = hook.Type();
		if ((type & HOOK_ADDITIONAL) && (type & HOOK_ENGINE) == 0)
		{
			std::unique_ptr<CHAR[]> name(new CHAR[hook.NameLength()]);
			if (ReadProcessMemory(pr.process_handle, hook.Name(), name.get(), hook.NameLength(), NULL))
			{
				if (hook.hp.module)
				{
					HookParam hp = hook.hp;
					MakeHookRelative(pr, hp);
					pf.AddHook(hook_ptr(new HookProfile(hp, toUnicodeString(name.get()))));
				}
				else
					pf.AddHook(hook_ptr(new HookProfile(hook.hp, toUnicodeString(name.get()))));
			}
		}
	}
	ReleaseMutex(pr.hookman_mutex);
}

void MakeHookRelative(const ProcessRecord& pr, HookParam& hp)
{
	MEMORY_BASIC_INFORMATION info;
	VirtualQueryEx(pr.process_handle, (LPCVOID)hp.address, &info, sizeof(info));
	hp.address -= (DWORD)info.AllocationBase;
	hp.function = 0;
}

void HookManager::AddThreadsToProfile(Profile& pf, const ProcessRecord& pr, DWORD pid)
{
	HM_LOCK;
	AddThreadToProfile(pf, pr, current);
}

DWORD AddThreadToProfile(Profile& pf, const ProcessRecord& pr, TextThread* thread)
{
	const ThreadParameter* tp = thread->GetThreadParameter();
	std::wstring hook_name = GetHookNameByAddress(pr, tp->hook);
	if (hook_name.empty())
		return -1;
	auto thread_profile = new ThreadProfile(hook_name, tp->retn, tp->spl, 0, 0,
		THREAD_MASK_RETN | THREAD_MASK_SPLIT, L"");
	DWORD threads_size = pf.Threads().size();
	int thread_profile_index = pf.AddThread(thread_ptr(thread_profile));
	if (thread_profile_index == threads_size) // new thread
	{
		WORD iw = thread_profile_index & 0xFFFF;
		if (thread->Status() & CURRENT_SELECT)
			pf.SelectedIndex() = iw;
	}
	return thread_profile_index; // in case more than one thread links to the same thread
}

// EOF

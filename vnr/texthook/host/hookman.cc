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
#include "profile/pugixml.hpp"
#include "profile/misc.h"

#define DEBUG "vnrhost/hookman.cc"
#include "sakurakit/skdebug.h"

namespace { // unnamed
//enum { MAX_ENTRY = 0x40 };

#define HM_LOCK win_mutex_lock<HookManager::mutex_type> d_locker(hmcs) // Synchronized scope for accessing private data


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
  NtWaitForSingleObject(pr->hookman_mutex, 0, 0);
  Hook *hks = (Hook *)pr->hookman_map;
  for (int i = 0; i < MAX_HOOK; i++)
    if (hks[i].Address() == hook_addr) {
      len = hks[i].NameLength();
      if (len >= max)
        len = max;
      NtReadVirtualMemory(pr->process_handle, hks[i].Name(), str, len, &len);
      if (str[len - 1] == 0)
        len--;
      else
        str[len] = 0;
      break;
    }

  NtReleaseMutant(pr->hookman_mutex, 0);
  //::man->UnlockProcessHookman(pid);
  return len;
}

void ThreadTable::SetThread(DWORD num, TextThread *ptr)
{
  int number = num;
  if (number >= size) {
    while (number >= size)
      size <<= 1;
    TextThread **temp;
    //if (size < 0x10000) {
      temp = new TextThread*[size];
      if (size > used)
        ::memset(temp, 0, (size - used) * sizeof(TextThread *)); // jichi 9/21/2013: zero memory
      memcpy(temp, storage, used * sizeof(TextThread *));
    //}
    delete[] storage;
    storage = temp;
  }
  storage[number] = ptr;
  if (ptr == nullptr) {
    if (number == used - 1)
      while (storage[used - 1] == 0)
        used--;
  } else if (number >= used)
    used = number + 1;
}

TextThread *ThreadTable::FindThread(DWORD number)
{ return number <= (DWORD)used ? storage[number] : nullptr; }

static const char sse_table_eq[0x100]={
  -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
  -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, //1, compare 2
  -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
  -1,-1,-1,-1, 1,1,1,1, -1,-1,-1,-1, 1,1,1,1, //3, compare 3
  -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
  -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, //1, compare 2
  -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
  -1,-1,-1,-1, -1,-1,-1,-1, 1,1,1,1, 1,1,1,1, //7, compare 4
  -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
  -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, //1, compare 2
  -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
  -1,-1,-1,-1, 1,1,1,1, -1,-1,-1,-1, 1,1,1,1, //3, compare 3
  -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
  -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, -1,-1,1,1, //1, compare 2
  -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, -1,1,-1,1, //0, compare 1
  0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 //f, equal
};

char TCmp::operator()(const ThreadParameter* t1, const ThreadParameter* t2)
  //SSE speed up. Compare four integers in const time without branching.
  //The AVL tree branching operation needs 2 bit of information.
  //One bit for equality and one bit for "less than" or "greater than".

{
  union{__m128 m0;__m128i i0;};
  union{__m128 m1;__m128i i1;};
  union{__m128 m2;__m128i i2;};
  int k0,k1;
  i1 = _mm_loadu_si128((const __m128i*)t1);
  i2 = _mm_loadu_si128((const __m128i*)t2);
  i0 = _mm_cmpgt_epi32(i1,i2);
  k0 = _mm_movemask_ps(m0);
  i1 = _mm_cmpeq_epi32(i1,i2);
  k1 = _mm_movemask_ps(m1);
  return sse_table_eq[k1*16+k0];
}
void TCpy::operator()(ThreadParameter* t1, const ThreadParameter* t2)
{ memcpy(t1,t2,sizeof(ThreadParameter)); }

int TLen::operator()(const ThreadParameter* t) { return 0; }

// Artikash 5/31/2018: required for unordered_map to work with struct key
bool operator==(const ThreadParameter& one, const ThreadParameter& two)
{
	return one.pid == two.pid && one.hook == two.hook && one.retn == two.retn && one.spl == two.spl;
}

#define NAMED_PIPE_DISCONNECT 1
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
  , current_pid(0)
  , thread_table(nullptr)
  , destroy_event(nullptr)
  , register_count(0)
  , new_thread_number(0)
	, threadTable()
	, processRecordsByIds()
{
  // jichi 9/21/2013: zero memory
  ::memset(record, 0, sizeof(record));
  ::memset(text_pipes, 0, sizeof(text_pipes));
  ::memset(cmd_pipes, 0, sizeof(cmd_pipes));
  ::memset(recv_threads, 0, sizeof(recv_threads));

  head.key = new ThreadParameter;
  head.key->pid = 0;
  head.key->hook = -1;
  head.key->retn = -1;
  head.key->spl = -1;
  head.data = 0;
  thread_table = new ThreadTable; // jichi 9/26/2013: zero memory in ThreadTable

  TextThread* consoleTextThread = threadTable[{0, -1UL, -1UL, -1UL}] = new TextThread(0, -1, -1, -1, threadTable.size());
  consoleTextThread->Status() |= USING_UNICODE;
  SetCurrent(consoleTextThread);

  TextThread *entry = new TextThread(0, -1,-1,-1, new_thread_number++);  // jichi 9/26/2013: zero memory in TextThread
  thread_table->SetThread(0, entry);
  SetCurrent(entry);
  entry->Status() |= USING_UNICODE;
  //texts->SetUnicode(true);
  //entry->AddToCombo();
  //entry->ComboSelectCurrent();

  //if (background==0) entry->AddToStore((BYTE*)BackgroundMsg,wcslen(BackgroundMsg)<<1,0,1);

  //InitializeCriticalSection(&hmcs);
  destroy_event = IthCreateEvent(0, 0, 0);
}

HookManager::~HookManager()
{
	// Artikash 5/31/2018: This is called when the program terminates, so Windows should automatically free all these resources.....right?
  //LARGE_INTEGER timeout={-1000*1000,-1};
  //IthBreak();
  //NtWaitForSingleObject(destroy_event, 0, 0);
  //NtClose(destroy_event);
  //NtClose(cmd_pipes[0]);
  //NtClose(recv_threads[0]);
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
  for (auto i : threadTable)
  {
	  if (i.second->PID() == pid && i.second->Addr() == addr)
	  {
		  if (remove)
		  {
			  remove(i.second);
		  }
		  delete i.second;
		  threadTable[i.first] = nullptr;
	  }
  }
  SetCurrent(0);
}
void HookManager::RemoveSingleThread(DWORD number)
{
  if (number == 0)
    return;
  HM_LOCK;
  for (auto i : threadTable)
  {
	  if (i.second->Number() == number)
	  {
		  if (remove)
		  {
			  remove(i.second);
		  }
		  delete i.second;
		  threadTable[i.first] = nullptr;
	  }
  }
  SetCurrent(0);
}

void HookManager::RemoveProcessContext(DWORD pid)
{
  HM_LOCK;
  for (auto i : threadTable)
  {
	  if (i.second->PID() == pid)
	  {
		  if (remove)
		  {
			  remove(i.second);
		  }
		  delete i.second;
		  threadTable[i.first] = nullptr;
	  }
  }
  SetCurrent(0);
}
void HookManager::RegisterThread(TextThread* it, DWORD num)
{ thread_table->SetThread(num, it); }

void HookManager::RegisterPipe(HANDLE text, HANDLE cmd, HANDLE thread)
{
  text_pipes[register_count] = text;
  cmd_pipes[register_count] = cmd;
  recv_threads[register_count] = thread;
  register_count++;
  if (register_count == 1)
    NtSetEvent(destroy_event, 0);
  else
    NtClearEvent(destroy_event);
}
void HookManager::RegisterProcess(DWORD pid)
{
  HM_LOCK;
  wchar_t str[0x40],
          path[MAX_PATH];
  //pid_map->Set(pid>>2);
  //ConsoleOutput("vnrhost:RegisterProcess: lock");
  //EnterCriticalSection(&hmcs);
  record[register_count - 1].pid_register = pid;
  //record[register_count - 1].engine_register = engine;
  swprintf(str, ITH_SECTION_ L"%d", pid);
  HANDLE hSection = IthCreateSection(str, HOOK_SECTION_SIZE, PAGE_READONLY);
  LPVOID map = nullptr;
  //DWORD map_size = 0x1000;
  DWORD map_size = HOOK_SECTION_SIZE / 2; // jichi 1/16/2015: Changed to half to hook section size
  //if (::ith_has_section)
  NtMapViewOfSection(hSection, NtCurrentProcess(),
      &map, 0, map_size, 0, &map_size, ViewUnmap, 0,
      PAGE_READONLY);

  record[register_count - 1].hookman_section = hSection;
  record[register_count - 1].hookman_map = map;

  HANDLE hProc;
  CLIENT_ID id;
  id.UniqueProcess = pid;
  id.UniqueThread = 0;
  OBJECT_ATTRIBUTES oa = {};
  oa.uLength = sizeof(oa);
  if (NT_SUCCESS(NtOpenProcess(&hProc,
      PROCESS_QUERY_INFORMATION|
      PROCESS_CREATE_THREAD|
      PROCESS_VM_READ|
      PROCESS_VM_WRITE|
      PROCESS_VM_OPERATION,
      &oa,&id)))
    record[register_count - 1].process_handle = hProc;
  else {
    DOUT("failed to open process");
    //::man->AddConsoleOutput(ErrorOpenProcess);
    //LeaveCriticalSection(&hmcs);
    //ConsoleOutput("vnrhost:RegisterProcess: unlock");
    return;
  }

  // jichi 9/27/2013: The hook man should be consistent with the one defined in vnrcli
  //Hook *h = (Hook *)map;
  //for (int i = 0; i < MAX_HOOK; i++)
  //  if (!h[i].hook_name)
  //    break;
  //  else {
  //    const Hook &hi = h[i];
  //    wchar_t buffer[1000];
  //    DWORD len = hi.NameLength();
  //    NtReadVirtualMemory(hProc, hi.hook_name, buffer, len << 1, &len);
  //    buffer[len] = 0;
  //    ITH_MSG(buffer);
  //  }

  swprintf(str, ITH_HOOKMAN_MUTEX_ L"%d", pid);
  record[register_count - 1].hookman_mutex = IthOpenMutex(str);
  current_pid = pid;
  if (attach)
    attach(pid);
  //LeaveCriticalSection(&hmcs);
  //ConsoleOutput("vnrhost:RegisterProcess: unlock");
}

void HookManager::UnRegisterProcess(DWORD pid)
{
  HM_LOCK;
  //ConsoleOutput("vnrhost:UnRegisterProcess: lock");
  //EnterCriticalSection(&hmcs);

  int i;
  for (i = 0; i < MAX_REGISTER; i++)
    if(record[i].pid_register == pid)
      break;

  if (i < MAX_REGISTER) {
    NtClose(text_pipes[i]);
    NtClose(cmd_pipes[i]);
    NtClose(recv_threads[i]);
    NtClose(record[i].hookman_mutex);

    //if (::ith_has_section)
    NtUnmapViewOfSection(NtCurrentProcess(), record[i].hookman_map);
    //else
    //  delete[] record[i].hookman_map;

    NtClose(record[i].process_handle);
    NtClose(record[i].hookman_section);

    for (; i < MAX_REGISTER; i++) {
      record[i] = record[i+1];
      text_pipes[i] = text_pipes[i+1];
      cmd_pipes[i] = cmd_pipes[i+1];
      recv_threads[i] = recv_threads[i+1];
      if (text_pipes[i] == 0)
        break;
    }
    register_count--;
    if (current_pid == pid)
      current_pid = register_count ? record[0].pid_register : 0;
    RemoveProcessContext(pid);
  }
  //pid_map->Clear(pid>>2);

  if (register_count == 1)
    NtSetEvent(destroy_event, 0);
  //LeaveCriticalSection(&hmcs);
  //ConsoleOutput("vnrhost:UnRegisterProcess: unlock");
  if (detach)
    detach(pid);
}

// jichi 9/28/2013: I do not need this
//void HookManager::SetName(DWORD type)
//{
//  WCHAR c;
//  if (type & PRINT_DWORD)
//    c = L'H';
//  else if (type & USING_UNICODE) {
//    if (type & STRING_LAST_CHAR)
//      c = L'L';
//    else if (type & USING_STRING)
//      c = L'Q';
//    else
//      c = L'W';
//  } else {
//    if (type & USING_STRING)
//      c = L'S';
//    else if (type & BIG_ENDIAN)
//      c = L'A';
//    else
//      c = L'B';
//  }
//  //swprintf(user_entry,L"UserHook%c",c);
//}

void HookManager::DispatchText(DWORD pid, const BYTE *text, DWORD hook, DWORD retn, DWORD spl, int len, bool space)
{
  // jichi 20/27/2013: When PID is zero, the text comes from console, which I don't need
  if (!text || !pid || (len <= 0 && !space))
    return;
  HM_LOCK;
  //bool flag=false;
  ThreadParameter tp = {pid, hook, retn, spl};
  //ConsoleOutput("vnrhost:DispatchText: lock");
  //EnterCriticalSection(&hmcs);
  TextThread *it;
  //`try {
    if (TreeNode<ThreadParameter *,DWORD> *in = Search(&tp)) {
      DWORD number = in->data;
      it = thread_table->FindThread(number);
    } else if (IsFull()) { // jichi 1/16/2015: Skip adding threads when full
      static bool once = true; // output only once
      if (once) {
        once = false;
        DOUT("so many new threads, skip");
      }
      return;
    } else { // New thread
      Insert(&tp, new_thread_number);
      it = new TextThread(pid, hook, retn, spl, new_thread_number);
      RegisterThread(it, new_thread_number);
      DOUT("found new thread");
      char entstr[0x200];
      it->GetEntryString(entstr);
      DOUT(entstr);
      while (thread_table->FindThread(++new_thread_number));
      if (create)
        create(it);
    }
    if (it)
      it->AddText(text, len, false, space); // jichi 10/27/2013: new line is false
    //LeaveCriticalSection(&hmcs);
    //ConsoleOutput("vnrhost:DispatchText: unlock");
  //} catch (...) {
  //  // ignored
  //}
}

void HookManager::AddConsoleOutput(LPCWSTR text)
{
  if (text) {
    int len = wcslen(text) << 1;
    TextThread *console = thread_table->FindThread(0);
    //EnterCriticalSection(&hmcs);
    console->AddText((BYTE*)text,len,false,true);
    console->AddText((BYTE*)L"\r\n",4,false,true);
    //LeaveCriticalSection(&hmcs);
  }
}

void HookManager::ClearText(DWORD pid, DWORD hook, DWORD retn, DWORD spl)
{
  HM_LOCK;
  //bool flag=false;
  //ConsoleOutput("vnrhost:ClearText: lock");
  //EnterCriticalSection(&hmcs);
  ThreadParameter tp = {pid, hook, retn, spl};
  if (TreeNode<ThreadParameter *, DWORD> *in = Search(&tp))
    if (TextThread *it = thread_table->FindThread(in->data)) {
      it->Reset();
      //SetCurrent(it);
      if (reset)
        reset(it);
      //it->ResetEditText();
    }

  //LeaveCriticalSection(&hmcs);
  //ConsoleOutput("vnrhost:ClearText: unlock");
}
void HookManager::ClearCurrent()
{
  HM_LOCK;
  //ConsoleOutput("vnrhost:ClearCurrent: lock");
  //EnterCriticalSection(&hmcs);
  if (current) {
    current->Reset();
    if (reset)
      reset(current);
  }
  //current->ResetEditText();
  //LeaveCriticalSection(&hmcs);
  //ConsoleOutput("vnrhost:ClearCurrent: unlock");
}
void HookManager::ResetRepeatStatus()
{
  HM_LOCK;
  //ConsoleOutput("vnrhost:ResetRepeatStatus: lock");
  //EnterCriticalSection(&hmcs);
  for (int i = 1; i < thread_table->Used(); i++)
    if (TextThread *it = thread_table->FindThread(i))
      it->ResetRepeatStatus();

  //LeaveCriticalSection(&hmcs);
  //ConsoleOutput("vnrhost:ResetRepeatStatus: unlock");
}
//void HookManager::LockHookman(){ EnterCriticalSection(&hmcs); }
//void HookManager::UnlockHookman(){ LeaveCriticalSection(&hmcs); }

/*void HookManager::SetProcessEngineType(DWORD pid, DWORD type)
{
  int i;
  for (i=0;i<MAX_REGISTER;i++)
    if (record[i].pid_register==pid) break;
  if (i<MAX_REGISTER)
  {
    record[i].engine_register|=type;
  }
}*/

ProcessRecord *HookManager::GetProcessRecord(DWORD pid)
{
  HM_LOCK;
  //EnterCriticalSection(&hmcs);
  for (int i = 0; i < MAX_REGISTER; i++)
    if (record[i].pid_register == pid)
      return record + i;
  return nullptr;
  //ProcessRecord *pr = i < MAX_REGISTER ? record + i : nullptr;
  //LeaveCriticalSection(&hmcs);
  //return pr;
}

HANDLE HookManager::GetCmdHandleByPID(DWORD pid)
{
  HM_LOCK;
  //EnterCriticalSection(&hmcs);
  for (int i = 0; i < MAX_REGISTER; i++)
    if (record[i].pid_register == pid)
      return cmd_pipes[i];
  return nullptr;
  //HANDLE h = i < MAX_REGISTER ? cmd_pipes[i] : 0;
  //LeaveCriticalSection(&hmcs);
  //return h;
}

MK_BASIC_TYPE(DWORD)
MK_BASIC_TYPE(LPVOID)

//DWORD Hash(LPCWSTR module, int length)
//{
//  bool flag = (length==-1);
//  DWORD hash = 0;
//  for (;*module && (flag || length--); module++)
//    hash = ((hash>>7)|(hash<<25)) + *module;
//  return hash;
//}

HANDLE  GetCmdHandleByPID(DWORD pid) { return ::man->GetCmdHandleByPID(pid); }

//void AddLink(WORD from, WORD to) { ::man->AddLink(from, to); }

// jichi 9/27/2013: Unparse to hook parameters /H code
void GetCode(const HookParam &hp, LPWSTR buffer, DWORD pid)
{
  WCHAR c;
  LPWSTR ptr = buffer;
  // jichi 12/7/2014: disabled
  //if (hp.type&PRINT_DWORD)
  //  c = L'H';
  if (hp.type&USING_UNICODE) {
    if (hp.type&USING_STRING)
      c = L'Q';
    else if (hp.type&STRING_LAST_CHAR)
      c = L'L';
    else
      c = L'W';
  } else {
    if (hp.type&USING_STRING)
      c = L'S';
    else if (hp.type&BIG_ENDIAN)
      c = L'A';
    else if (hp.type&STRING_LAST_CHAR)
      c = L'E';
    else
      c = L'B';
  }
  ptr += swprintf(ptr, L"/H%c",c);
  if (hp.type & NO_CONTEXT)
    *ptr++ = L'N';
  if (hp.offset>>31)
    ptr += swprintf(ptr, L"-%X",-(hp.offset+4));
  else
    ptr += swprintf(ptr, L"%X",hp.offset);
  if (hp.type & DATA_INDIRECT) {
    if (hp.index>>31)
      ptr += swprintf(ptr, L"*-%X",-hp.index);
    else
      ptr += swprintf(ptr,L"*%X",hp.index);
  }
  if (hp.type & USING_SPLIT) {
    if (hp.split >> 31)
      ptr += swprintf(ptr, L":-%X", -(4 + hp.split));
    else
      ptr += swprintf(ptr, L":%X", hp.split);
  }
  if (hp.type & SPLIT_INDIRECT) {
    if (hp.split_index >> 31)
      ptr += swprintf(ptr, L"*-%X", -hp.split_index);
    else
      ptr += swprintf(ptr, L"*%X", hp.split_index);
  }
  if (hp.module) {
    if (pid) {
      WCHAR path[MAX_PATH];
      MEMORY_BASIC_INFORMATION info;
      ProcessRecord* pr = ::man->GetProcessRecord(pid);
      if (pr) {
        HANDLE hProc = pr->process_handle;
        if (NT_SUCCESS(NtQueryVirtualMemory(hProc,(PVOID)hp.address, MemorySectionName, path, MAX_PATH*2, 0)) &&
            NT_SUCCESS(NtQueryVirtualMemory(hProc,(PVOID)hp.address, MemoryBasicInformation, &info, sizeof(info), 0)))
          ptr += swprintf(ptr, L"@%X:%s", hp.address - (DWORD)info. AllocationBase, wcsrchr(path,L'\\') + 1);
      }
    } else {
      ptr += swprintf(ptr, L"@%X!%X", hp.address, hp.module);
      if (hp.function)
        ptr += swprintf(ptr, L"!%X", hp.function);
    }
  }
  else
    ptr += swprintf(ptr, L"@%X", hp.address);
}

// jichi 1/16/2015
bool HookManager::IsFull() const { return new_thread_number >= MAX_HOOK; }

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
	for (int i = 0; i < thread_table->Used(); ++i)
	{
		TextThread* tt = thread_table->FindThread(i);
		if (tt == NULL || tt->GetThreadParameter()->pid != pid)
			continue;
		//if (tt->Status() & CURRENT_SELECT || tt->Link() || tt->GetComment())
		if (tt->Status() & CURRENT_SELECT || tt->Link())
			AddThreadToProfile(pf, pr, tt);
	}
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
		if (thread->Link())
		{
			WORD to_index = AddThreadToProfile(pf, pr, thread->Link()) & 0xFFFF;
			if (iw >= 0)
				pf.AddLink(link_ptr(new LinkProfile(iw, to_index)));
		}
	}
	return thread_profile_index; // in case more than one thread links to the same thread
}

// EOF

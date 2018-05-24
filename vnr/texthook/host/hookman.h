#pragma once

// hookman.h
// 8/23/2013 jichi
// Branch: ITH/HookManager.h, rev 133

#include "host/avl_p.h"
#include "host/textthread.h"
#include "winmutex/winmutex.h"

namespace pugi {
	class xml_node;
}
class Profile;

enum { MAX_REGISTER = 0xf };
enum { MAX_PREV_REPEAT_LENGTH = 0x20 };

struct ProcessRecord {
  DWORD pid_register;
  DWORD hookman_register;
  DWORD module_register;
  //DWORD engine_register; // jichi 10/19/2014: removed
  HANDLE process_handle;
  HANDLE hookman_mutex;
  HANDLE hookman_section;
  LPVOID hookman_map;
};

class ThreadTable : public MyVector<TextThread *, 0x40>
{
public:
  virtual void SetThread(DWORD number, TextThread *ptr);
  virtual TextThread *FindThread(DWORD number);
};

struct IHFSERVICE TCmp { char operator()(const ThreadParameter *t1, const ThreadParameter *t2); };
struct IHFSERVICE TCpy { void operator()(ThreadParameter *t1, const ThreadParameter *t2); };
struct IHFSERVICE TLen { int operator()(const ThreadParameter *t); };

typedef DWORD (*ProcessEventCallback)(DWORD pid);

class IHFSERVICE HookManager : public AVLTree<ThreadParameter, DWORD, TCmp, TCpy, TLen>
{
public:
  HookManager();
  ~HookManager();
  // jichi 12/26/2013: remove virtual modifiers
  TextThread *FindSingle(DWORD number);
  ProcessRecord *GetProcessRecord(DWORD pid);
  void RemoveSingleThread(DWORD number);
  //void LockHookman();
  //void UnlockHookman();
  void ResetRepeatStatus();
  void ClearCurrent();
  void AddLink(WORD from, WORD to);
  void UnLink(WORD from);
  void UnLinkAll(WORD from);
  void SelectCurrent(DWORD num);
  void DetachProcess(DWORD pid);
  void SetCurrent(TextThread *it);
  void AddConsoleOutput(LPCWSTR text);

  // jichi 10/27/2013: Add const; add space.
  void DispatchText(DWORD pid, const BYTE *text, DWORD hook, DWORD retn, DWORD split, int len, bool space);

  void ClearText(DWORD pid, DWORD hook, DWORD retn, DWORD split); // private
  void RemoveProcessContext(DWORD pid); // private
  void RemoveSingleHook(DWORD pid, DWORD addr);
  void RegisterThread(TextThread*, DWORD); // private
  void RegisterPipe(HANDLE text, HANDLE cmd, HANDLE thread);
  void RegisterProcess(DWORD pid);
  void UnRegisterProcess(DWORD pid);
  //void SetName(DWORD);

  HANDLE GetCmdHandleByPID(DWORD pid);

  ConsoleCallback RegisterConsoleCallback(ConsoleCallback cf)
  { return (ConsoleCallback)_InterlockedExchange((long*)&console,(long)cf); }

  ConsoleWCallback RegisterConsoleWCallback(ConsoleWCallback cf)
  { return (ConsoleWCallback)_InterlockedExchange((long*)&wconsole,(long)cf); }

  ThreadEventCallback RegisterThreadCreateCallback(ThreadEventCallback cf)
  { return (ThreadEventCallback)_InterlockedExchange((long*)&create,(long)cf); }

  ThreadEventCallback RegisterThreadRemoveCallback(ThreadEventCallback cf)
  { return (ThreadEventCallback)_InterlockedExchange((long*)&remove,(long)cf); }

  ThreadEventCallback RegisterThreadResetCallback(ThreadEventCallback cf)
  { return (ThreadEventCallback)_InterlockedExchange((long*)&reset,(long)cf); }

  ThreadEventCallback RegisterAddRemoveLinkCallback(ThreadEventCallback cf)
  { return (ThreadEventCallback)_InterlockedExchange((long*)&addRemoveLink, (long)cf); }

  ProcessEventCallback RegisterProcessAttachCallback(ProcessEventCallback cf)
  { return (ProcessEventCallback)_InterlockedExchange((long*)&attach,(long)cf); }

  ProcessEventCallback RegisterProcessDetachCallback(ProcessEventCallback cf)
  { return (ProcessEventCallback)_InterlockedExchange((long*)&detach,(long)cf); }

  ProcessEventCallback RegisterProcessNewHookCallback(ProcessEventCallback cf)
  { return (ProcessEventCallback)_InterlockedExchange((long*)&hook,(long)cf); }

  ProcessEventCallback ProcessNewHook() { return hook; }
  TextThread *GetCurrentThread() { return current; } // private
  ProcessRecord *Records() { return record; } // private
  ThreadTable *Table() { return thread_table; } // private

  //DWORD& SplitTime() { return split_time; }
  //DWORD& RepeatCount() { return repeat_count; }
  //DWORD& CyclicRemove() { return cyclic_remove; }
  //DWORD& GlobalFilter() { return global_filter; }
  void ConsoleOutput(LPCSTR text) { if (console) console(text); } // not thread safe
  void ConsoleOutputW(LPCWSTR text) { if (wconsole) wconsole(text); } // not thread safe

  void OnThreadCreate(pugi::xml_node profile_node, TextThread* thread);
  void GetProfile(DWORD pid, pugi::xml_node profile_node);

private:
  typedef win_mutex<CRITICAL_SECTION> mutex_type;
  mutex_type hmcs;

  TextThread *current;
  ConsoleCallback console; // jichi 12/25/2013: add console output callback
  ConsoleWCallback wconsole;
  ThreadEventCallback create,
                      remove,
                      reset,
					  addRemoveLink;
  ProcessEventCallback attach,
                       detach,
                       hook;
  DWORD current_pid;
  ThreadTable *thread_table;
  HANDLE destroy_event;
  ProcessRecord record[MAX_REGISTER + 1];
  HANDLE text_pipes[MAX_REGISTER + 1],
         cmd_pipes[MAX_REGISTER + 1],
         recv_threads[MAX_REGISTER + 1];
  WORD register_count,
       new_thread_number;

  // jichi 1/16/2014: Stop adding new threads when full
  bool IsFull() const; // { return new_thread_number >= MAX_HOOK; }
  bool IsEmpty() const { return !new_thread_number; }
  void HookManager::AddThreadsToProfile(Profile& pf, const ProcessRecord& pr, DWORD pid);
};

// EOF

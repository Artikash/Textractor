#pragma once

// hookman.h
// 8/23/2013 jichi
// Branch: ITH/HookManager.h, rev 133

#include "config.h"
#include "host/textthread.h"
#include "winmutex/winmutex.h"
#include <unordered_map>

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
  HANDLE hostPipe;
};

typedef DWORD (*ProcessEventCallback)(DWORD pid);

struct ThreadParameterHasher
{
	size_t operator()(const ThreadParameter& tp) const
	{
		return std::hash<DWORD>()(tp.pid << 6) + std::hash<DWORD>()(tp.hook) + std::hash<DWORD>()(tp.retn) + std::hash<DWORD>()(tp.spl);
	}
};

class IHFSERVICE HookManager
{
public:
  HookManager();
  ~HookManager();
  // jichi 12/26/2013: remove virtual modifiers
  TextThread *FindSingle(DWORD number);
  ProcessRecord *GetProcessRecord(DWORD pid);
  //void LockHookman();
  //void UnlockHookman();
  void ClearCurrent();
  void SelectCurrent(DWORD num);
  void SetCurrent(TextThread *it);
  void AddConsoleOutput(LPCWSTR text);

  // jichi 10/27/2013: Add const; add space.
  void DispatchText(DWORD pid, const BYTE *text, DWORD hook, DWORD retn, DWORD split, int len);
  void RemoveProcessContext(DWORD pid); // private
  void RemoveSingleHook(DWORD pid, DWORD addr);
  void RegisterProcess(DWORD pid, HANDLE hostPipe);
  void UnRegisterProcess(DWORD pid);
  //void SetName(DWORD);

  HANDLE GetHostPipeByPID(DWORD pid);

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

  void OnThreadCreate(pugi::xml_node profile_node, TextThread* thread);
  void GetProfile(DWORD pid, pugi::xml_node profile_node);

private:
	std::unordered_map<ThreadParameter, TextThread*, ThreadParameterHasher> threadTable;
	std::unordered_map<DWORD, ProcessRecord*> processRecordsByIds;

  CRITICAL_SECTION hmcs;

  TextThread *current;
  ThreadEventCallback create,
                      remove,
                      reset,
					  addRemoveLink;
  ProcessEventCallback attach,
                       detach,
                       hook;
  WORD register_count,
       new_thread_number;

  void HookManager::AddThreadsToProfile(Profile& pf, const ProcessRecord& pr, DWORD pid);
};

// EOF

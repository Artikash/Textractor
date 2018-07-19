#pragma once

// hookman.h
// 8/23/2013 jichi
// Branch: ITH/HookManager.h, rev 133

#include "config.h"
#include "textthread.h"
#include "winmutex/winmutex.h"
#include <unordered_map>
#include <string>
#include "vnrhook/include/types.h"

struct ProcessRecord {
  HANDLE process_handle;
  HANDLE hookman_mutex;
  HANDLE hookman_section;
  LPVOID hookman_map;
  HANDLE hostPipe;
};

typedef DWORD(*ProcessEventCallback)(DWORD pid);
typedef DWORD(*ThreadEventCallback)(TextThread*);

struct ThreadParameterHasher
{
	size_t operator()(const ThreadParameter& tp) const
	{
		return std::hash<DWORD>()(tp.pid << 6) + std::hash<DWORD>()(tp.hook) + std::hash<DWORD>()(tp.retn) + std::hash<DWORD>()(tp.spl);
	}
};

class DLLEXPORT HookManager
{
public:
  HookManager();
  ~HookManager();
  TextThread *FindSingle(DWORD number);
  ProcessRecord *GetProcessRecord(DWORD pid);
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
  HookParam GetHookParam(DWORD pid, DWORD addr);
  std::wstring GetHookName(DWORD pid, DWORD addr);
  //void SetName(DWORD);

  HANDLE GetHostPipe(DWORD pid);

  void RegisterThreadCreateCallback(ThreadEventCallback cf) { create = cf; }
  void RegisterThreadRemoveCallback(ThreadEventCallback cf) { remove = cf; }
  void RegisterThreadResetCallback(ThreadEventCallback cf) { reset = cf; }
  void RegisterProcessAttachCallback(ProcessEventCallback cf) { attach = cf; }
  void RegisterProcessDetachCallback(ProcessEventCallback cf) { detach = cf; }

  void SetSplitInterval(unsigned int splitDelay) { this->splitDelay = splitDelay; }

private:
	std::unordered_map<ThreadParameter, TextThread*, ThreadParameterHasher> textThreadsByParams;
	std::unordered_map<DWORD, ProcessRecord*> processRecordsByIds;

  CRITICAL_SECTION hmcs;

  TextThread *current;
  ThreadEventCallback create,
	  remove,
	  reset;
  ProcessEventCallback attach,
	  detach;
  WORD register_count,
	  new_thread_number;

  unsigned int splitDelay;
};

// EOF

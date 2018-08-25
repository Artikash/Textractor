#pragma once

// host.h
// 8/23/2013 jichi
// Branch: ITH/IHF.h, rev 105

#include "common.h"
#include "textthread.h"

typedef std::function<void(DWORD)> ProcessEventCallback;
typedef std::function<void(TextThread*)> ThreadEventCallback;

namespace Host
{
	void Start(ProcessEventCallback onAttach, ProcessEventCallback onDetach, ThreadEventCallback onCreate, ThreadEventCallback onRemove);
	void Close();

	bool InjectProcess(DWORD pid, DWORD timeout = 5000);
	void DetachProcess(DWORD pid);

	void InsertHook(DWORD pid, HookParam hp, std::string name = "");
	void RemoveHook(DWORD pid, unsigned __int64 addr);

	HookParam GetHookParam(DWORD pid, unsigned __int64 addr);
	HookParam GetHookParam(ThreadParam tp);
	std::wstring GetHookName(DWORD pid, unsigned __int64 addr);

	TextThread* GetThread(ThreadParam tp);
	void AddConsoleOutput(std::wstring text);
}
// EOF

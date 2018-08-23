#pragma once

// host.h
// 8/23/2013 jichi
// Branch: ITH/IHF.h, rev 105

#include "common.h"
#include "textthread.h"

#define DLLEXPORT __declspec(dllexport)

typedef std::function<void(DWORD)> ProcessEventCallback;
typedef std::function<void(TextThread*)> ThreadEventCallback;

namespace Host
{
	DLLEXPORT void Start(ProcessEventCallback onAttach, ProcessEventCallback onDetach, ThreadEventCallback onCreate, ThreadEventCallback onRemove);
	DLLEXPORT void Close();
	DLLEXPORT bool InjectProcess(DWORD pid, DWORD timeout = 5000);
	DLLEXPORT bool DetachProcess(DWORD pid);

	DLLEXPORT bool InsertHook(DWORD pid, HookParam hp, std::string name = "");
	DLLEXPORT bool RemoveHook(DWORD pid, DWORD addr);
	DLLEXPORT HookParam GetHookParam(DWORD pid, DWORD addr);
	DLLEXPORT HookParam GetHookParam(ThreadParam tp);
	DLLEXPORT std::wstring GetHookName(DWORD pid, DWORD addr);

	DLLEXPORT TextThread* GetThread(ThreadParam tp);
	DLLEXPORT void AddConsoleOutput(std::wstring text);
}

void DispatchText(ThreadParam tp, const BYTE *text, int len);
void RemoveThreads(bool(*RemoveIf)(ThreadParam, ThreadParam), ThreadParam cmp);
void RegisterProcess(DWORD pid, HANDLE hostPipe);
void UnregisterProcess(DWORD pid);

// EOF

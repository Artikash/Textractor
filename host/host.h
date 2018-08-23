#pragma once

// host.h
// 8/23/2013 jichi
// Branch: ITH/IHF.h, rev 105

#include "common.h"
#include "textthread.h"
#include "../vnrhook/include/types.h"

#define DLLEXPORT __declspec(dllexport)

struct ProcessRecord
{
	HANDLE processHandle;
	HANDLE sectionMutex;
	HANDLE section;
	LPVOID sectionMap;
	HANDLE hostPipe;
};

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
	DLLEXPORT HookParam GetHookParam(ThreadParameter tp);
	DLLEXPORT std::wstring GetHookName(DWORD pid, DWORD addr);

	DLLEXPORT TextThread* GetThread(ThreadParameter tp);
	DLLEXPORT void AddConsoleOutput(std::wstring text);
}

void DispatchText(ThreadParameter tp, const BYTE *text, int len);
void RemoveThreads(bool(*RemoveIf)(ThreadParameter, ThreadParameter), ThreadParameter cmp);
void RegisterProcess(DWORD pid, HANDLE hostPipe);
void UnregisterProcess(DWORD pid);

// EOF

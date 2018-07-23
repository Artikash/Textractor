#pragma once

// host.h
// 8/23/2013 jichi
// Branch: ITH/IHF.h, rev 105

#define DLLEXPORT __declspec(dllexport)

#include <Windows.h>
#include "textthread.h"
#include <string>
#include "../vnrhook/include/types.h"

struct ProcessRecord
{
	HANDLE process_handle;
	HANDLE hookman_mutex;
	HANDLE hookman_section;
	LPVOID hookman_map;
	HANDLE hostPipe;
};

typedef void(*ProcessEventCallback)(DWORD pid);
typedef void(*ThreadEventCallback)(TextThread*);

struct ThreadParameterHasher
{
	size_t operator()(const ThreadParameter& tp) const
	{
		return std::hash<DWORD>()(tp.pid << 6) + std::hash<DWORD>()(tp.hook) + std::hash<DWORD>()(tp.retn) + std::hash<DWORD>()(tp.spl);
	}
};

namespace Host
{
	DLLEXPORT void Open();
	DLLEXPORT bool Start();
	DLLEXPORT void Close();
	DLLEXPORT bool InjectProcess(DWORD pid, DWORD timeout = 5000);
	DLLEXPORT bool DetachProcess(DWORD pid);

	DLLEXPORT bool InsertHook(DWORD pid, HookParam hp, std::string name = "");
	DLLEXPORT bool RemoveHook(DWORD pid, DWORD addr);
	DLLEXPORT HookParam GetHookParam(DWORD pid, DWORD addr);
	DLLEXPORT std::wstring GetHookName(DWORD pid, DWORD addr);

	DLLEXPORT TextThread* GetThread(DWORD number);
	DLLEXPORT void AddConsoleOutput(std::wstring text);

	DLLEXPORT void RegisterThreadCreateCallback(ThreadEventCallback cf);
	DLLEXPORT void RegisterThreadRemoveCallback(ThreadEventCallback cf);
	DLLEXPORT void RegisterProcessAttachCallback(ProcessEventCallback cf);
	DLLEXPORT void RegisterProcessDetachCallback(ProcessEventCallback cf);
}

void DispatchText(DWORD pid, DWORD hook, DWORD retn, DWORD split, const BYTE *text, int len);
void RemoveThreads(bool(*RemoveIf)(ThreadParameter, ThreadParameter), ThreadParameter cmp);
void RegisterProcess(DWORD pid, HANDLE hostPipe);
void UnregisterProcess(DWORD pid);

// EOF

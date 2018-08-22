// host.cc
// 8/24/2013 jichi
// Branch IHF/main.cpp, rev 111

#include "host.h"
#include "pipe.h"
#include "winmutex.h"
#include <mutex>
#include <thread>
#include <atlbase.h>
#include "../vnrhook/include/const.h"
#include "../vnrhook/include/defs.h"
#include "../vnrhook/include/types.h"
#include <unordered_map>

std::unordered_map<ThreadParameter, TextThread*, ThreadParameterHasher> textThreadsByParams;
std::unordered_map<DWORD, ProcessRecord> processRecordsByIds;

std::recursive_mutex hostMutex;

ThreadEventCallback OnCreate, OnRemove;
ProcessEventCallback OnAttach, OnDetach;

DWORD DUMMY[100];

#define HOST_LOCK std::lock_guard<std::recursive_mutex> hostLocker(hostMutex) // Synchronized scope for accessing private data

namespace Host
{

	DLLEXPORT void Start(ProcessEventCallback onAttach, ProcessEventCallback onDetach, ThreadEventCallback onCreate, ThreadEventCallback onRemove)
	{
		OnAttach = onAttach; OnDetach = onDetach; OnCreate = onCreate; OnRemove = onRemove;
		OnCreate(textThreadsByParams[{ 0, -1UL, -1UL, -1UL }] = new TextThread({ 0, -1UL, -1UL, -1UL }, USING_UNICODE));
		CreateNewPipe();
	}

	DLLEXPORT void Close()
	{
		// Artikash 7/25/2018: This is only called when NextHooker is closed, at which point Windows should free everything itself...right?
		HOST_LOCK;
		for (auto i : processRecordsByIds) UnregisterProcess(i.first);
	}

	DLLEXPORT bool InjectProcess(DWORD processId, DWORD timeout)
	{
		if (processId == GetCurrentProcessId()) return false;

		CloseHandle(CreateMutexW(nullptr, FALSE, (ITH_HOOKMAN_MUTEX_ + std::to_wstring(processId)).c_str()));
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			AddConsoleOutput(L"already injected");
			return false;
		}

		HMODULE textHooker = LoadLibraryExW(ITH_DLL, nullptr, DONT_RESOLVE_DLL_REFERENCES);
		wchar_t textHookerPath[MAX_PATH];
		unsigned int textHookerPathSize = GetModuleFileNameW(textHooker, textHookerPath, MAX_PATH) * 2 + 2;
		FreeLibrary(textHooker);

		if (HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId))
			if (LPVOID remoteData = VirtualAllocEx(processHandle, nullptr, textHookerPathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
				if (WriteProcessMemory(processHandle, remoteData, textHookerPath, textHookerPathSize, nullptr))
					if (HANDLE thread = CreateRemoteThread(processHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, remoteData, 0, nullptr))
					{
						WaitForSingleObject(thread, timeout);
						CloseHandle(thread);
						VirtualFreeEx(processHandle, remoteData, 0, MEM_RELEASE);
						CloseHandle(processHandle);
						return true;
					}

		AddConsoleOutput(L"couldn't inject dll");
		return false;
	}

	DLLEXPORT bool DetachProcess(DWORD processId)
	{
		DWORD command = HOST_COMMAND_DETACH;
		return WriteFile(processRecordsByIds[processId].hostPipe, &command, sizeof(command), DUMMY, nullptr);
	}

	DLLEXPORT bool InsertHook(DWORD pid, HookParam hp, std::string name)
	{
		BYTE buffer[PIPE_BUFFER_SIZE] = {};
		*(DWORD*)buffer = HOST_COMMAND_NEW_HOOK;
		*(HookParam*)(buffer + sizeof(DWORD)) = hp;
		if (name.size()) strcpy((char*)buffer + sizeof(DWORD) + sizeof(HookParam), name.c_str());
		return WriteFile(processRecordsByIds[pid].hostPipe, buffer, sizeof(DWORD) + sizeof(HookParam) + name.size(), DUMMY, nullptr);
	}

	DLLEXPORT bool RemoveHook(DWORD pid, DWORD addr)
	{
		BYTE buffer[sizeof(DWORD) * 2] = {};
		*(DWORD*)buffer = HOST_COMMAND_REMOVE_HOOK;
		*(DWORD*)(buffer + sizeof(DWORD)) = addr;
		return WriteFile(processRecordsByIds[pid].hostPipe, buffer, sizeof(DWORD) * 2, DUMMY, nullptr);
	}

	DLLEXPORT HookParam GetHookParam(DWORD pid, DWORD addr)
	{
		HOST_LOCK;
		HookParam ret = {};
		ProcessRecord pr = processRecordsByIds[pid];
		if (pr.hookman_map == nullptr) return ret;
		MutexLocker locker(pr.hookman_mutex);
		const Hook* hooks = (const Hook*)pr.hookman_map;
		for (int i = 0; i < MAX_HOOK; ++i)
			if ((DWORD)hooks[i].Address() == addr)
				ret = hooks[i].hp;
		return ret;
	}

	DLLEXPORT HookParam GetHookParam(ThreadParameter tp) { return GetHookParam(tp.pid, tp.hook); }

	DLLEXPORT std::wstring GetHookName(DWORD pid, DWORD addr)
	{
		if (pid == 0) return L"Console";
		HOST_LOCK;
		std::string buffer = "";
		ProcessRecord pr = processRecordsByIds[pid];
		if (pr.hookman_map == nullptr) return L"";
		MutexLocker locker(pr.hookman_mutex);
		const Hook* hooks = (const Hook*)pr.hookman_map;
		for (int i = 0; i < MAX_HOOK; ++i)
			if ((DWORD)hooks[i].Address() == addr)
			{
				buffer.resize(hooks[i].NameLength());
				ReadProcessMemory(pr.process_handle, hooks[i].Name(), &buffer[0], hooks[i].NameLength(), nullptr);
			}
		USES_CONVERSION;
		return std::wstring(A2W(buffer.c_str()));
	}

	DLLEXPORT TextThread* GetThread(ThreadParameter tp)
	{
		HOST_LOCK;
		return textThreadsByParams[tp];
	}

	DLLEXPORT void AddConsoleOutput(std::wstring text)
	{
		HOST_LOCK;
		textThreadsByParams[{ 0, -1UL, -1UL, -1UL }]->AddSentence(std::wstring(text));
	}
}

void DispatchText(ThreadParameter tp, const BYTE* text, int len)
{
	if (!text || len <= 0) return;
	HOST_LOCK;
	TextThread *it;
	if ((it = textThreadsByParams[tp]) == nullptr)
		OnCreate(it = textThreadsByParams[tp] = new TextThread(tp, Host::GetHookParam(tp).type));
	it->AddText(text, len);
}

void RemoveThreads(bool(*RemoveIf)(ThreadParameter, ThreadParameter), ThreadParameter cmp)
{
	HOST_LOCK;
	std::vector<ThreadParameter> removedThreads;
	for (auto i : textThreadsByParams)
		if (RemoveIf(i.first, cmp))
		{
			OnRemove(i.second);
			//delete i.second; // Artikash 7/24/2018: FIXME: Qt GUI updates on another thread, so I can't delete this yet.
			removedThreads.push_back(i.first);
		}
	for (auto i : removedThreads) textThreadsByParams.erase(i);
}

void RegisterProcess(DWORD pid, HANDLE hostPipe)
{
	HOST_LOCK;
	ProcessRecord record;
	record.hostPipe = hostPipe;
	record.hookman_section = OpenFileMappingW(FILE_MAP_READ, FALSE, (ITH_SECTION_ + std::to_wstring(pid)).c_str());
	record.hookman_map = MapViewOfFile(record.hookman_section, FILE_MAP_READ, 0, 0, HOOK_SECTION_SIZE / 2); // jichi 1/16/2015: Changed to half to hook section size
	record.process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	record.hookman_mutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, (ITH_HOOKMAN_MUTEX_ + std::to_wstring(pid)).c_str());
	processRecordsByIds[pid] = record;
	OnAttach(pid);
}

void UnregisterProcess(DWORD pid)
{
	HOST_LOCK;
	ProcessRecord pr = processRecordsByIds[pid];
	if (!pr.hostPipe) return;
	CloseHandle(pr.hookman_mutex);
	UnmapViewOfFile(pr.hookman_map);
	CloseHandle(pr.process_handle);
	CloseHandle(pr.hookman_section);
	processRecordsByIds[pid] = {};
	RemoveThreads([](auto one, auto two) { return one.pid == two.pid; }, { pid, 0, 0, 0 });
	OnDetach(pid);
}

// EOF

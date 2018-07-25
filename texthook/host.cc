// host.cc
// 8/24/2013 jichi
// Branch IHF/main.cpp, rev 111

#include "host.h"
#include "pipe.h"
#include "winmutex.h"
#include <atlbase.h>
#include "../vnrhook/include/const.h"
#include "../vnrhook/include/defs.h"
#include "../vnrhook/include/types.h"
#include <unordered_map>

HANDLE preventDuplicationMutex;

std::unordered_map<ThreadParameter, TextThread*, ThreadParameterHasher> textThreadsByParams;
std::unordered_map<DWORD, ProcessRecord> processRecordsByIds;

CRITICAL_SECTION hostCs;

ThreadEventCallback onCreate, onRemove;
ProcessEventCallback onAttach, onDetach;

WORD nextThreadNumber;
HWND dummyWindow;

#define HOST_LOCK CriticalSectionLocker hostLocker(hostCs) // Synchronized scope for accessing private data

void GetDebugPrivileges() // Artikash 5/19/2018: Is it just me or is this function 100% superfluous?
{
	HANDLE processToken;
	TOKEN_PRIVILEGES Privileges = { 1, {0x14, 0, SE_PRIVILEGE_ENABLED} };
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken);
	AdjustTokenPrivileges(processToken, FALSE, &Privileges, 0, nullptr, nullptr);
	CloseHandle(processToken);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID unused)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hinstDLL);
		// jichi 8/24/2013: Create hidden window so that ITH can access timer and events
		dummyWindow = CreateWindowW(L"Button", L"InternalWindow", 0, 0, 0, 0, 0, 0, 0, hinstDLL, 0);
		break;
	default:
		break;
	}
	return true;
}

namespace Host
{
	DLLEXPORT bool Start()
	{
		preventDuplicationMutex = CreateMutexW(nullptr, TRUE, ITH_SERVER_MUTEX);
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			MessageBoxW(nullptr, L"I am sorry that this game is attached by some other VNR ><\nPlease restart the game and try again!", L"Error", MB_ICONERROR);
			return false;
		}
		else
		{
			GetDebugPrivileges();
			InitializeCriticalSection(&hostCs);
			onAttach = onDetach = nullptr;
			onCreate = onRemove = nullptr;
			nextThreadNumber = 0;
			return true;
		}
	}

	DLLEXPORT void Open()
	{
		TextThread* console = textThreadsByParams[{ 0, -1UL, -1UL, -1UL }] = new TextThread({ 0, -1UL, -1UL, -1UL }, nextThreadNumber++);
		console->Status() |= USING_UNICODE;
		if (onCreate) onCreate(console);
		CreateNewPipe();
	}

	DLLEXPORT void Close()
	{
		// Artikash 7/25/2018: This is only called when NextHooker is closed, at which point Windows should free everything itself...right?
		//EnterCriticalSection(&hostCs);
		//DestroyWindow(dummyWindow);
		//RemoveThreads([](auto one, auto two) { return true; }, {});
		////for (auto i : processRecordsByIds) UnregisterProcess(i.first); // Artikash 7/24/2018 FIXME: This segfaults since UnregisterProcess invalidates the iterator
		//LeaveCriticalSection(&hostCs);
		//DeleteCriticalSection(&hostCs);
		//CloseHandle(preventDuplicationMutex);
	}

	DLLEXPORT bool InjectProcess(DWORD processId, DWORD timeout)
	{
		if (processId == GetCurrentProcessId()) return false;

		CloseHandle(CreateMutexW(nullptr, FALSE, (ITH_HOOKMAN_MUTEX_ + std::to_wstring(processId)).c_str()));
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			AddConsoleOutput(L"already locked");
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
		DWORD unused;
		return WriteFile(processRecordsByIds[processId].hostPipe, &command, sizeof(command), &unused, nullptr);
	}

	DLLEXPORT bool InsertHook(DWORD pid, HookParam hp, std::string name)
	{
		BYTE buffer[PIPE_BUFFER_SIZE] = {};
		*(DWORD*)buffer = HOST_COMMAND_NEW_HOOK;
		*(HookParam*)(buffer + sizeof(DWORD)) = hp;
		if (name.size()) strcpy((char*)buffer + sizeof(DWORD) + sizeof(HookParam), name.c_str());
		DWORD unused;
		return WriteFile(processRecordsByIds[pid].hostPipe, buffer, sizeof(DWORD) + sizeof(HookParam) + name.size(), &unused, nullptr);
	}

	DLLEXPORT bool RemoveHook(DWORD pid, DWORD addr)
	{
		HANDLE hostPipe = processRecordsByIds[pid].hostPipe;
		if (hostPipe == nullptr) return false;
		HANDLE hookRemovalEvent = CreateEventW(nullptr, TRUE, FALSE, ITH_REMOVEHOOK_EVENT);
		BYTE buffer[sizeof(DWORD) * 2] = {};
		*(DWORD*)buffer = HOST_COMMAND_REMOVE_HOOK;
		*(DWORD*)(buffer + sizeof(DWORD)) = addr;
		DWORD unused;
		WriteFile(hostPipe, buffer, sizeof(DWORD) * 2, &unused, nullptr);
		WaitForSingleObject(hookRemovalEvent, 1000);
		CloseHandle(hookRemovalEvent);
		RemoveThreads([](auto one, auto two) { return one.pid == two.pid && one.hook == two.hook; }, { pid, addr, 0, 0 });
		return true;
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
			if (hooks[i].Address() == addr)
				ret = hooks[i].hp;
		return ret;
	}

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
			if (hooks[i].Address() == addr)
			{
				buffer.resize(hooks[i].NameLength());
				ReadProcessMemory(pr.process_handle, hooks[i].Name(), &buffer[0], hooks[i].NameLength(), nullptr);
			}
		USES_CONVERSION;
		return std::wstring(A2W(buffer.c_str()));
	}

	DLLEXPORT TextThread* GetThread(DWORD number)
	{
		HOST_LOCK;
		for (auto i : textThreadsByParams)
			if (i.second->Number() == number)
				return i.second;
		return nullptr;
	}

	DLLEXPORT void AddConsoleOutput(std::wstring text)
	{
		HOST_LOCK;
		textThreadsByParams[{ 0, -1UL, -1UL, -1UL }]->AddSentence(std::wstring(text));
	}

	DLLEXPORT void RegisterThreadCreateCallback(ThreadEventCallback cf) { onCreate = cf; }
	DLLEXPORT void RegisterThreadRemoveCallback(ThreadEventCallback cf) { onRemove = cf; }
	DLLEXPORT void RegisterProcessAttachCallback(ProcessEventCallback cf) { onAttach = cf; }
	DLLEXPORT void RegisterProcessDetachCallback(ProcessEventCallback cf) { onDetach = cf; }
}

void DispatchText(DWORD pid, DWORD hook, DWORD retn, DWORD split, const BYTE * text, int len)
{
	// jichi 2/27/2013: When PID is zero, the text comes from console, which I don't need
	if (!text || !pid || len <= 0) return;
	HOST_LOCK;
	ThreadParameter tp = { pid, hook, retn, split };
	TextThread *it;
	if ((it = textThreadsByParams[tp]) == nullptr)
	{
		it = textThreadsByParams[tp] = new TextThread(tp, nextThreadNumber++);
		if (Host::GetHookParam(pid, hook).type & USING_UNICODE) it->Status() |= USING_UNICODE;
		if (onCreate) onCreate(it);
	}
	it->AddText(text, len);
}

void RemoveThreads(bool(*RemoveIf)(ThreadParameter, ThreadParameter), ThreadParameter cmp)
{
	HOST_LOCK;
	std::vector<ThreadParameter> removedThreads;
	for (auto i : textThreadsByParams)
		if (RemoveIf(i.first, cmp))
		{
			if (onRemove) onRemove(i.second);
			//delete i.second; // Artikash 7/24/2018: FIXME: Qt GUI updates on another thread, so I can't delete this yet.
			i.second->Clear(); // Temp workaround to free some memory.
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
	if (onAttach) onAttach(pid);
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
	processRecordsByIds.erase(pid);
	RemoveThreads([](auto one, auto two) { return one.pid == two.pid; }, { pid, 0, 0, 0 });
	if (onDetach) onDetach(pid);
}

// EOF

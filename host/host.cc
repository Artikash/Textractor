// host.cc
// 8/24/2013 jichi
// Branch IHF/main.cpp, rev 111

#include "host.h"
#include "pipe.h"
#include "const.h"
#include "defs.h"
#include "../vnrhook/hijack/texthook.h"

struct ProcessRecord
{
	HANDLE processHandle;
	HANDLE sectionMutex;
	HANDLE section;
	LPVOID sectionMap;
	HANDLE hostPipe;
};

// Artikash 5/31/2018: required for unordered_map to work with struct key
template <> struct std::hash<ThreadParam> { size_t operator()(const ThreadParam& tp) const { return std::hash<__int64>()((tp.pid + tp.hook) ^ (tp.retn + tp.spl)); } };
bool operator==(const ThreadParam& one, const ThreadParam& two) { return one.pid == two.pid && one.hook == two.hook && one.retn == two.retn && one.spl == two.spl; }

// Artikash 7/20/2018: similar to std::lock guard but use Winapi objects for cross process comms
class MutexLocker
{
	HANDLE mutex;
public:
	MutexLocker(HANDLE mutex) : mutex(mutex) { WaitForSingleObject(mutex, 0); }
	~MutexLocker() { if (mutex != INVALID_HANDLE_VALUE && mutex != nullptr) ReleaseMutex(mutex); }
};

std::unordered_map<ThreadParam, TextThread*> textThreadsByParams;
std::unordered_map<DWORD, ProcessRecord> processRecordsByIds;

std::recursive_mutex hostMutex;

ThreadEventCallback OnCreate, OnRemove;
ProcessEventCallback OnAttach, OnDetach;

DWORD DUMMY[100];

ThreadParam CONSOLE{ 0, -1ULL, -1ULL, -1ULL };

#define HOST_LOCK std::lock_guard<std::recursive_mutex> hostLocker(hostMutex) // Synchronized scope for accessing private data

namespace Host
{
	DLLEXPORT void Start(ProcessEventCallback onAttach, ProcessEventCallback onDetach, ThreadEventCallback onCreate, ThreadEventCallback onRemove)
	{
		OnAttach = onAttach; OnDetach = onDetach; OnCreate = onCreate; OnRemove = onRemove;
		OnCreate(textThreadsByParams[CONSOLE] = new TextThread(CONSOLE, USING_UNICODE));
		CreatePipe();
	}

	DLLEXPORT void Close()
	{
		// Artikash 7/25/2018: This is only called when NextHooker is closed, at which point Windows should free everything itself...right?
#ifdef _DEBUG // Check memory leaks
		HOST_LOCK;
		OnRemove = [](TextThread* textThread) { delete textThread; };
		for (auto i : processRecordsByIds) UnregisterProcess(i.first);
		delete textThreadsByParams[CONSOLE];
#endif
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
		{
#ifdef _WIN64
			BOOL invalidProcess = FALSE;
			IsWow64Process(processHandle, &invalidProcess);
			if (invalidProcess)
			{
				AddConsoleOutput(L"architecture mismatch: try 32 bit NextHooker instead");
				CloseHandle(processHandle);
				return false;
			}
#endif
			if (LPVOID remoteData = VirtualAllocEx(processHandle, nullptr, textHookerPathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
			{
				WriteProcessMemory(processHandle, remoteData, textHookerPath, textHookerPathSize, nullptr);
				if (HANDLE thread = CreateRemoteThread(processHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, remoteData, 0, nullptr))
				{
					WaitForSingleObject(thread, timeout);
					CloseHandle(thread);
					VirtualFreeEx(processHandle, remoteData, 0, MEM_RELEASE);
					CloseHandle(processHandle);
					return true;
				}
				VirtualFreeEx(processHandle, remoteData, 0, MEM_RELEASE);
				CloseHandle(processHandle);
			}
		}

		AddConsoleOutput(L"couldn't inject dll");
		return false;
	}

	DLLEXPORT bool DetachProcess(DWORD processId)
	{
		int command = HOST_COMMAND_DETACH;
		return WriteFile(processRecordsByIds[processId].hostPipe, &command, sizeof(command), DUMMY, nullptr);
	}

	DLLEXPORT bool InsertHook(DWORD pid, HookParam hp, std::string name)
	{
		auto info = InsertHookCmd(hp, name);
		return WriteFile(processRecordsByIds[pid].hostPipe, &info, sizeof(info), DUMMY, nullptr);
	}

	DLLEXPORT bool RemoveHook(DWORD pid, unsigned __int64 addr)
	{
		auto info = RemoveHookCmd(addr);
		return WriteFile(processRecordsByIds[pid].hostPipe, &info, sizeof(info), DUMMY, nullptr);
	}

	DLLEXPORT HookParam GetHookParam(DWORD pid, unsigned __int64 addr)
	{
		HOST_LOCK;
		HookParam ret = {};
		ProcessRecord pr = processRecordsByIds[pid];
		if (pr.sectionMap == nullptr) return ret;
		MutexLocker locker(pr.sectionMutex);
		const TextHook* hooks = (const TextHook*)pr.sectionMap;
		for (int i = 0; i < MAX_HOOK; ++i)
			if (hooks[i].Address() == addr)
				ret = hooks[i].hp;
		return ret;
	}

	DLLEXPORT HookParam GetHookParam(ThreadParam tp) { return GetHookParam(tp.pid, tp.hook); }

	DLLEXPORT std::wstring GetHookName(DWORD pid, unsigned __int64 addr)
	{
		if (pid == 0) return L"Console";
		HOST_LOCK;
		std::string buffer = "";
		ProcessRecord pr = processRecordsByIds[pid];
		if (pr.sectionMap == nullptr) return L"";
		MutexLocker locker(pr.sectionMutex);
		const TextHook* hooks = (const TextHook*)pr.sectionMap;
		for (int i = 0; i < MAX_HOOK; ++i)
			if (hooks[i].Address() == addr)
			{
				buffer.resize(hooks[i].NameLength());
				ReadProcessMemory(pr.processHandle, hooks[i].Name(), &buffer[0], hooks[i].NameLength(), nullptr);
			}
		USES_CONVERSION;
		return std::wstring(A2W(buffer.c_str()));
	}

	DLLEXPORT TextThread* GetThread(ThreadParam tp)
	{
		HOST_LOCK;
		return textThreadsByParams[tp];
	}

	DLLEXPORT void AddConsoleOutput(std::wstring text)
	{
		HOST_LOCK;
		textThreadsByParams[CONSOLE]->AddSentence(std::wstring(text));
	}
}

void DispatchText(ThreadParam tp, const BYTE* text, int len)
{
	if (!text || len <= 0) return;
	HOST_LOCK;
	TextThread *it;
	if ((it = textThreadsByParams[tp]) == nullptr)
		OnCreate(it = textThreadsByParams[tp] = new TextThread(tp, Host::GetHookParam(tp).type));
	it->AddText(text, len);
}

void RemoveThreads(bool(*RemoveIf)(ThreadParam, ThreadParam), ThreadParam cmp)
{
	HOST_LOCK;
	std::vector<ThreadParam> removedThreads;
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
	record.section = OpenFileMappingW(FILE_MAP_READ, FALSE, (ITH_SECTION_ + std::to_wstring(pid)).c_str());
	record.sectionMap = MapViewOfFile(record.section, FILE_MAP_READ, 0, 0, HOOK_SECTION_SIZE / 2); // jichi 1/16/2015: Changed to half to hook section size
	record.processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	record.sectionMutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, (ITH_HOOKMAN_MUTEX_ + std::to_wstring(pid)).c_str());
	processRecordsByIds[pid] = record;
	OnAttach(pid);
}

void UnregisterProcess(DWORD pid)
{
	HOST_LOCK;
	ProcessRecord pr = processRecordsByIds[pid];
	if (!pr.hostPipe) return;
	CloseHandle(pr.sectionMutex);
	UnmapViewOfFile(pr.sectionMap);
	CloseHandle(pr.processHandle);
	CloseHandle(pr.section);
	processRecordsByIds[pid] = {};
	RemoveThreads([](auto one, auto two) { return one.pid == two.pid; }, { pid, 0, 0, 0 });
	OnDetach(pid);
}

// EOF

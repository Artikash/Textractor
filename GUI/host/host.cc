// host.cc
// 8/24/2013 jichi
// Branch IHF/main.cpp, rev 111

#include "host.h"
#include "const.h"
#include "defs.h"
#include "../vnrhook/hijack/texthook.h"
#include <atlbase.h> // A2W

namespace
{
	struct ProcessRecord
	{
		HANDLE processHandle;
		HANDLE sectionMutex;
		HANDLE section;
		LPVOID sectionMap;
		HANDLE hostPipe;
	};

	ThreadEventCallback OnCreate, OnRemove;
	ProcessEventCallback OnAttach, OnDetach;

	std::unordered_map<ThreadParam, TextThread*> textThreadsByParams;
	std::unordered_map<DWORD, ProcessRecord> processRecordsByIds;

	std::recursive_mutex hostMutex;

	DWORD DUMMY[100];
	ThreadParam CONSOLE{ 0, -1ULL, -1ULL, -1ULL };

	void DispatchText(ThreadParam tp, const BYTE* text, int len)
	{
		if (!text || len <= 0) return;
		LOCK(hostMutex);
		TextThread *it;
		if ((it = textThreadsByParams[tp]) == nullptr)
			OnCreate(it = textThreadsByParams[tp] = new TextThread(tp, Host::GetHookParam(tp).type));
		it->AddText(text, len);
	}

	void RemoveThreads(std::function<bool(ThreadParam)> removeIf)
	{
		LOCK(hostMutex);
		std::vector<ThreadParam> removedThreads;
		for (auto i : textThreadsByParams)
			if (removeIf(i.first))
			{
				OnRemove(i.second);
				//delete i.second; // Artikash 7/24/2018: FIXME: Qt GUI updates on another thread, so I can't delete this yet.
				removedThreads.push_back(i.first);
			}
		for (auto i : removedThreads) textThreadsByParams.erase(i);
	}

	void RegisterProcess(DWORD pid, HANDLE hostPipe)
	{
		LOCK(hostMutex);
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
		LOCK(hostMutex);
		ProcessRecord pr = processRecordsByIds[pid];
		if (!pr.hostPipe) return;
		CloseHandle(pr.sectionMutex);
		UnmapViewOfFile(pr.sectionMap);
		CloseHandle(pr.processHandle);
		CloseHandle(pr.section);
		processRecordsByIds[pid] = {};
		RemoveThreads([&](ThreadParam tp) { return tp.pid == pid; });
		OnDetach(pid);
	}

	void StartPipe()
	{
		std::thread([]
		{
			SECURITY_DESCRIPTOR pipeSD = {};
			InitializeSecurityDescriptor(&pipeSD, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&pipeSD, TRUE, NULL, FALSE); // Allow non-admin processes to connect to pipe created by admin host
			SECURITY_ATTRIBUTES pipeSA = { sizeof(SECURITY_ATTRIBUTES), &pipeSD, FALSE };
			HANDLE hookPipe = CreateNamedPipeW(ITH_TEXT_PIPE, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, MAXDWORD, &pipeSA);
			HANDLE hostPipe = CreateNamedPipeW(ITH_COMMAND_PIPE, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, MAXDWORD, &pipeSA);
			ConnectNamedPipe(hookPipe, nullptr);

			BYTE buffer[PIPE_BUFFER_SIZE + 1] = {};
			DWORD bytesRead, processId;
			ReadFile(hookPipe, &processId, sizeof(processId), &bytesRead, nullptr);
			RegisterProcess(processId, hostPipe);

			// jichi 9/27/2013: why recursion?
			// Artikash 5/20/2018: Easy way to create a new pipe for another process
			StartPipe();

			while (ReadFile(hookPipe, buffer, PIPE_BUFFER_SIZE, &bytesRead, nullptr))
				switch (*(int*)buffer)
				{
					//case HOST_NOTIFICATION_NEWHOOK:	// Artikash 7/18/2018: Useless for now, but could be used to implement smth later
					//break;
				case HOST_NOTIFICATION_RMVHOOK:
				{
					auto info = *(HookRemovedNotif*)buffer;
					RemoveThreads([&](ThreadParam tp) { return tp.pid == processId && tp.hook == info.address; });
				}
				break;
				case HOST_NOTIFICATION_TEXT:
				{
					auto info = *(ConsoleOutputNotif*)buffer;
					USES_CONVERSION;
					Host::AddConsoleOutput(A2W(info.message));
				}
				break;
				default:
				{
					ThreadParam tp = *(ThreadParam*)buffer;
					buffer[bytesRead] = 0;
					buffer[bytesRead + 1] = 0;
					DispatchText(tp, buffer + sizeof(tp), bytesRead - sizeof(tp));
				}
				break;
				}

			DisconnectNamedPipe(hookPipe);
			DisconnectNamedPipe(hostPipe);
			UnregisterProcess(processId);
			CloseHandle(hookPipe);
			CloseHandle(hostPipe);
		}).detach();
	}
}

namespace Host
{
	void Start(ProcessEventCallback onAttach, ProcessEventCallback onDetach, ThreadEventCallback onCreate, ThreadEventCallback onRemove)
	{
		OnAttach = onAttach; OnDetach = onDetach; OnCreate = onCreate; OnRemove = onRemove;
		OnCreate(textThreadsByParams[CONSOLE] = new TextThread(CONSOLE, USING_UNICODE));
		StartPipe();
	}

	void Close()
	{
		// Artikash 7/25/2018: This is only called when NextHooker is closed, at which point Windows should free everything itself...right?
#ifdef _DEBUG // Check memory leaks
		LOCK(hostMutex);
		OnRemove = [](TextThread* textThread) { delete textThread; };
		for (auto i : processRecordsByIds) UnregisterProcess(i.first);
		delete textThreadsByParams[CONSOLE];
#endif
	}

	bool InjectProcess(DWORD processId, DWORD timeout)
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
		DWORD textHookerPathSize = GetModuleFileNameW(textHooker, textHookerPath, MAX_PATH) * 2 + 2;
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

	void DetachProcess(DWORD processId)
	{
		int command = HOST_COMMAND_DETACH;
		WriteFile(processRecordsByIds[processId].hostPipe, &command, sizeof(command), DUMMY, nullptr);
	}

	void InsertHook(DWORD pid, HookParam hp, std::string name)
	{
		auto info = InsertHookCmd(hp, name);
		WriteFile(processRecordsByIds[pid].hostPipe, &info, sizeof(info), DUMMY, nullptr);
	}

	void RemoveHook(DWORD pid, uint64_t addr)
	{
		auto info = RemoveHookCmd(addr);
		WriteFile(processRecordsByIds[pid].hostPipe, &info, sizeof(info), DUMMY, nullptr);
	}

	HookParam GetHookParam(DWORD pid, uint64_t addr)
	{
		LOCK(hostMutex);
		HookParam ret = {};
		ProcessRecord pr = processRecordsByIds[pid];
		if (pr.sectionMap == nullptr) return ret;
		WaitForSingleObject(pr.sectionMutex, 0);
		const TextHook* hooks = (const TextHook*)pr.sectionMap;
		for (int i = 0; i < MAX_HOOK; ++i)
			if (hooks[i].hp.address == addr)
				ret = hooks[i].hp;
		ReleaseMutex(pr.sectionMutex);
		return ret;
	}

	HookParam GetHookParam(ThreadParam tp) { return GetHookParam(tp.pid, tp.hook); }

	std::wstring GetHookName(DWORD pid, uint64_t addr)
	{
		if (pid == 0) return L"Console";
		LOCK(hostMutex);
		std::string buffer = "";
		ProcessRecord pr = processRecordsByIds[pid];
		if (pr.sectionMap == nullptr) return L"";
		WaitForSingleObject(pr.sectionMutex, 0);
		const TextHook* hooks = (const TextHook*)pr.sectionMap;
		for (int i = 0; i < MAX_HOOK; ++i)
			if (hooks[i].hp.address == addr)
			{
				buffer.resize(hooks[i].name_length);
				ReadProcessMemory(pr.processHandle, hooks[i].hook_name, &buffer[0], hooks[i].name_length, nullptr);
			}
		ReleaseMutex(pr.sectionMutex);
		USES_CONVERSION;
		return std::wstring(A2W(buffer.c_str()));
	}

	TextThread* GetThread(ThreadParam tp)
	{
		LOCK(hostMutex);
		return textThreadsByParams[tp];
	}

	void AddConsoleOutput(std::wstring text) { GetThread(CONSOLE)->AddSentence(std::wstring(text)); }
}

// EOF

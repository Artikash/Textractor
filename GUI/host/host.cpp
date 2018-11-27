#include "host.h"
#include "const.h"
#include "text.h"
#include "defs.h"
#include "util.h"
#include "../vnrhook/texthook.h"

namespace
{
	class ProcessRecord
	{
	public:
		inline static Host::ProcessEventCallback OnConnect, OnDisconnect;

		ProcessRecord(DWORD processId, HANDLE pipe) :
			processId(processId),
			pipe(pipe),
			fileMapping(OpenFileMappingW(FILE_MAP_READ, FALSE, (ITH_SECTION_ + std::to_wstring(processId)).c_str())),
			mappedView(MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, HOOK_SECTION_SIZE / 2)), // jichi 1/16/2015: Changed to half to hook section size
			sectionMutex(ITH_HOOKMAN_MUTEX_ + std::to_wstring(processId))
		{
			OnConnect(processId);
		}

		~ProcessRecord()
		{
			OnDisconnect(processId);
			UnmapViewOfFile(mappedView);
		}

		TextHook GetHook(uint64_t addr)
		{
			if (mappedView == nullptr) return {};
			LOCK(sectionMutex);
			auto hooks = (const TextHook*)mappedView;
			for (int i = 0; i < MAX_HOOK; ++i)
				if (hooks[i].hp.insertion_address == addr) return hooks[i];
			return {};
		}

		template <typename T>
		void Send(T data)
		{
			DWORD DUMMY;
			WriteFile(pipe, &data, sizeof(data), &DUMMY, nullptr);
		}

	private:
		DWORD processId;
		HANDLE pipe;
		AutoHandle<> fileMapping;
		LPCVOID mappedView;
		WinMutex sectionMutex;
	};

	ThreadSafePtr<std::unordered_map<ThreadParam, std::shared_ptr<TextThread>>> textThreadsByParams;
	ThreadSafePtr<std::unordered_map<DWORD, std::unique_ptr<ProcessRecord>>> processRecordsByIds;

	ThreadParam CONSOLE{ 0, -1ULL, -1ULL, -1ULL }, CLIPBOARD{ 0, 0, -1ULL, -1ULL };

	void RemoveThreads(std::function<bool(ThreadParam)> removeIf)
	{
		auto lockedTextThreadsByParams = textThreadsByParams.operator->();
		for (auto it = lockedTextThreadsByParams->begin(); it != lockedTextThreadsByParams->end(); removeIf(it->first) ? it = lockedTextThreadsByParams->erase(it) : ++it);
	}

	void CreatePipe()
	{
		std::thread([]
		{
			SECURITY_DESCRIPTOR pipeSD = {};
			InitializeSecurityDescriptor(&pipeSD, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&pipeSD, TRUE, NULL, FALSE); // Allow non-admin processes to connect to pipe created by admin host
			SECURITY_ATTRIBUTES pipeSA = { sizeof(SECURITY_ATTRIBUTES), &pipeSD, FALSE };
			AutoHandle<Util::NamedPipeHandleCloser>
				hookPipe = CreateNamedPipeW(HOOK_PIPE, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 0, PIPE_BUFFER_SIZE, MAXDWORD, &pipeSA),
				hostPipe = CreateNamedPipeW(HOST_PIPE, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, 0, MAXDWORD, &pipeSA);
			ConnectNamedPipe(hookPipe, nullptr);

			BYTE buffer[PIPE_BUFFER_SIZE] = {};
			DWORD bytesRead, processId;
			ReadFile(hookPipe, &processId, sizeof(processId), &bytesRead, nullptr);
			processRecordsByIds->insert({ processId, std::make_unique<ProcessRecord>(processId, hostPipe) });

			CreatePipe();

			while (ReadFile(hookPipe, buffer, PIPE_BUFFER_SIZE, &bytesRead, nullptr))
				switch (*(HostNotificationType*)buffer)
				{
				case HOST_NOTIFICATION_RMVHOOK:
				{
					auto info = *(HookRemovedNotif*)buffer;
					RemoveThreads([&](ThreadParam tp) { return tp.processId == processId && tp.addr == info.address; });
				}
				break;
				case HOST_NOTIFICATION_TEXT:
				{
					auto info = *(ConsoleOutputNotif*)buffer;
					Host::AddConsoleOutput(Util::StringToWideString(info.message).value());
				}
				break;
				default:
				{
					auto tp = *(ThreadParam*)buffer;
					if (textThreadsByParams->count(tp) == 0)
					{
						auto textThread = textThreadsByParams->insert({ tp, std::make_shared<TextThread>(tp, Host::GetHookParam(tp), Host::GetHookName(tp)) }).first->second;
						if (textThreadsByParams->size() > MAX_THREAD_COUNT)	Host::AddConsoleOutput(TOO_MANY_THREADS);
						else textThread->Start();
					}
					textThreadsByParams->at(tp)->Push(buffer + sizeof(tp), bytesRead - sizeof(tp));
				}
				break;
				}

			RemoveThreads([&](ThreadParam tp) { return tp.processId == processId; });
			processRecordsByIds->erase(processId);
		}).detach();
	}

	void StartCapturingClipboard()
	{
		std::thread([]
		{
			for (std::wstring last; true; Sleep(50))
				if (auto text = Util::GetClipboardText())
					if (last != text.value())
						Host::GetThread(CLIPBOARD)->AddSentence(last = text.value());
		}).detach();
	}
}

namespace Host
{
	void Start(ProcessEventCallback OnConnect, ProcessEventCallback OnDisconnect, TextThread::EventCallback OnCreate, TextThread::EventCallback OnDestroy, TextThread::OutputCallback Output)
	{
		ProcessRecord::OnConnect = OnConnect;
		ProcessRecord::OnDisconnect = OnDisconnect;
		TextThread::OnCreate = OnCreate;
		TextThread::OnDestroy = OnDestroy;
		TextThread::Output = Output;
		processRecordsByIds->insert({ CONSOLE.processId, std::make_unique<ProcessRecord>(CONSOLE.processId, INVALID_HANDLE_VALUE) });
		textThreadsByParams->insert({ CONSOLE, std::make_shared<TextThread>(CONSOLE, HookParam{}, L"Console") });
		textThreadsByParams->insert({ CLIPBOARD, std::make_shared<TextThread>(CLIPBOARD, HookParam{}, L"Clipboard") });
		StartCapturingClipboard();
		CreatePipe();
	}

	void Close()
	{
		// Artikash 7/25/2018: This is only called when Textractor is closed, at which point Windows should free everything itself...right?
#ifdef _DEBUG // Check memory leaks
		ProcessRecord::OnConnect = ProcessRecord::OnDisconnect = [](auto) {};
		TextThread::OnCreate = TextThread::OnDestroy = [](auto) {};
		processRecordsByIds->clear();
		textThreadsByParams->clear();
#endif
	}

	bool InjectProcess(DWORD processId, DWORD timeout)
	{
		if (processId == GetCurrentProcessId()) return false;

		WinMutex(ITH_HOOKMAN_MUTEX_ + std::to_wstring(processId));
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			AddConsoleOutput(ALREADY_INJECTED);
			return false;
		}

		static HMODULE vnrhook = LoadLibraryExW(ITH_DLL, nullptr, DONT_RESOLVE_DLL_REFERENCES);
		static std::wstring location = Util::GetModuleFileName(vnrhook).value();

		if (AutoHandle<> process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId))
		{
#ifdef _WIN64
			BOOL invalidProcess = FALSE;
			IsWow64Process(process, &invalidProcess);
			if (invalidProcess)
			{
				AddConsoleOutput(ARCHITECTURE_MISMATCH);
				return false;
			}
#endif
			if (LPVOID remoteData = VirtualAllocEx(process, nullptr, location.size() * 2 + 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
			{
				WriteProcessMemory(process, remoteData, location.c_str(), location.size() * 2 + 2, nullptr);
				if (AutoHandle<> thread = CreateRemoteThread(process, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, remoteData, 0, nullptr))
				{
					WaitForSingleObject(thread, timeout);
					VirtualFreeEx(process, remoteData, 0, MEM_RELEASE);
					return true;
				}
				VirtualFreeEx(process, remoteData, 0, MEM_RELEASE);
			}
		}

		AddConsoleOutput(INJECT_FAILED);
		return false;
	}

	void DetachProcess(DWORD processId)
	{
		processRecordsByIds->at(processId)->Send(HostCommandType(HOST_COMMAND_DETACH));
	}

	void InsertHook(DWORD processId, HookParam hp, std::string name)
	{
		processRecordsByIds->at(processId)->Send(InsertHookCmd(hp, name));
	}

	void RemoveHook(DWORD processId, uint64_t addr)
	{
		processRecordsByIds->at(processId)->Send(RemoveHookCmd(addr));
	}

	HookParam GetHookParam(DWORD processId, uint64_t addr)
	{
		return processRecordsByIds->at(processId)->GetHook(addr).hp;
	}

	std::wstring GetHookName(DWORD processId, uint64_t addr)
	{
		return Util::StringToWideString(processRecordsByIds->at(processId)->GetHook(addr).hookName).value();
	}

	std::shared_ptr<TextThread> GetThread(ThreadParam tp)
	{
		return textThreadsByParams->at(tp);
	}

	void AddConsoleOutput(std::wstring text) 
	{ 
		GetThread(CONSOLE)->AddSentence(text); 
	}
}

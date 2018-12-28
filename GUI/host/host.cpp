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
			mappedFile(OpenFileMappingW(FILE_MAP_READ, FALSE, (ITH_SECTION_ + std::to_wstring(processId)).c_str())),
			view(MapViewOfFile(mappedFile, FILE_MAP_READ, 0, 0, HOOK_SECTION_SIZE / 2)), // jichi 1/16/2015: Changed to half to hook section size
			viewMutex(ITH_HOOKMAN_MUTEX_ + std::to_wstring(processId))
		{
			OnConnect(processId);
		}

		~ProcessRecord()
		{
			OnDisconnect(processId);
			UnmapViewOfFile(view);
		}

		TextHook GetHook(uint64_t addr)
		{
			if (view == nullptr) return {};
			LOCK(viewMutex);
			auto hooks = (const TextHook*)view;
			for (int i = 0; i < MAX_HOOK; ++i)
				if (hooks[i].address == addr) return hooks[i];
			return {};
		}

		template <typename T>
		void Send(T data)
		{
			std::enable_if_t<sizeof(data) < PIPE_BUFFER_SIZE, DWORD> DUMMY;
			WriteFile(pipe, &data, sizeof(data), &DUMMY, nullptr);
		}

	private:
		DWORD processId;
		HANDLE pipe;
		AutoHandle<> mappedFile;
		LPCVOID view;
		WinMutex viewMutex;
	};

	ThreadSafe<std::unordered_map<ThreadParam, std::shared_ptr<TextThread>>> textThreadsByParams;
	ThreadSafe<std::unordered_map<DWORD, ProcessRecord>> processRecordsByIds;

	ThreadParam CONSOLE{ 0, -1ULL, -1ULL, -1ULL }, CLIPBOARD{ 0, 0, -1ULL, -1ULL };

	void RemoveThreads(std::function<bool(ThreadParam)> removeIf)
	{
		auto[lock, textThreadsByParams] = ::textThreadsByParams.operator->();
		for (auto it = textThreadsByParams->begin(); it != textThreadsByParams->end(); removeIf(it->first) ? it = textThreadsByParams->erase(it) : ++it);
	}

	void CreatePipe()
	{
		std::thread([]
		{
			SECURITY_DESCRIPTOR pipeSD = {};
			InitializeSecurityDescriptor(&pipeSD, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&pipeSD, TRUE, NULL, FALSE); // Allow non-admin processes to connect to pipe created by admin host
			SECURITY_ATTRIBUTES pipeSA = { sizeof(SECURITY_ATTRIBUTES), &pipeSD, FALSE };

			struct NamedPipeHandleCloser { void operator()(void* h) { DisconnectNamedPipe(h); CloseHandle(h); } };
			AutoHandle<NamedPipeHandleCloser>
				hookPipe = CreateNamedPipeW(HOOK_PIPE, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 0, PIPE_BUFFER_SIZE, MAXDWORD, &pipeSA),
				hostPipe = CreateNamedPipeW(HOST_PIPE, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, 0, MAXDWORD, &pipeSA);
			ConnectNamedPipe(hookPipe, nullptr);

			BYTE buffer[PIPE_BUFFER_SIZE] = {};
			DWORD bytesRead, processId;
			ReadFile(hookPipe, &processId, sizeof(processId), &bytesRead, nullptr);
			processRecordsByIds->try_emplace(processId, processId, hostPipe);

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
					if (textThreadsByParams->count(tp) == 0) textThreadsByParams->insert({ tp, std::make_shared<TextThread>(tp, Host::GetHookParam(tp)) });
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
		SetWindowsHookExW(WH_GETMESSAGE, [](int statusCode, WPARAM wParam, LPARAM lParam)
		{
			if (statusCode == HC_ACTION && wParam == PM_REMOVE && ((MSG*)lParam)->message == WM_CLIPBOARDUPDATE)
				if (auto text = Util::GetClipboardText()) Host::GetThread(CLIPBOARD)->PushSentence(text.value());
			return CallNextHookEx(NULL, statusCode, wParam, lParam);
		}, NULL, GetCurrentThreadId());
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
		processRecordsByIds->try_emplace(CONSOLE.processId, CONSOLE.processId, INVALID_HANDLE_VALUE);
		textThreadsByParams->insert({ CONSOLE, std::make_shared<TextThread>(CONSOLE, HookParam{}, L"Console") });
		textThreadsByParams->insert({ CLIPBOARD, std::make_shared<TextThread>(CLIPBOARD, HookParam{}, L"Clipboard") });
		StartCapturingClipboard();
		CreatePipe();
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
		static std::wstring location = Util::GetModuleFilename(vnrhook).value();

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
		processRecordsByIds->at(processId).Send(HostCommandType(HOST_COMMAND_DETACH));
	}

	void InsertHook(DWORD processId, HookParam hp)
	{
		processRecordsByIds->at(processId).Send(InsertHookCmd(hp));
	}

	HookParam GetHookParam(ThreadParam tp)
	{
		return processRecordsByIds->at(tp.processId).GetHook(tp.addr).hp;
	}

	std::shared_ptr<TextThread> GetThread(ThreadParam tp)
	{
		return textThreadsByParams->at(tp);
	}

	void AddConsoleOutput(std::wstring text)
	{
		GetThread(CONSOLE)->PushSentence(text);
	}
}

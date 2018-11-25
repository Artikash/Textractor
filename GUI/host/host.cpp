#include "host.h"
#include "const.h"
#include "text.h"
#include "defs.h"
#include "util.h"
#include "../vnrhook/texthook.h"
#include <sstream>

namespace
{
	char* GetCppExceptionInfo(EXCEPTION_POINTERS* exception)
	{
		// See https://blogs.msdn.microsoft.com/oldnewthing/20100730-00/?p=13273
		// Not very reliable so use __try
		__try { return ((char****)exception->ExceptionRecord->ExceptionInformation[2])[3][1][1] + 8; }
		__except (EXCEPTION_EXECUTE_HANDLER) { return "Could not find"; }
	}

	std::wstring lastError = L"Unknown error";

	LONG WINAPI ExceptionLogger(EXCEPTION_POINTERS* exception)
	{
		MEMORY_BASIC_INFORMATION info = {};
		VirtualQuery(exception->ExceptionRecord->ExceptionAddress, &info, sizeof(info));
		wchar_t moduleName[MAX_PATH] = {};
		GetModuleFileNameW((HMODULE)info.AllocationBase, moduleName, MAX_PATH);

		std::wstringstream errorMsg;
		errorMsg << std::uppercase << std::hex <<
			L"Error code: " << exception->ExceptionRecord->ExceptionCode << std::endl <<
			L"Error address: " << (uint64_t)exception->ExceptionRecord->ExceptionAddress << std::endl <<
			L"Error in module: " << moduleName << std::endl;

		if (exception->ExceptionRecord->ExceptionCode == 0xE06D7363)
			errorMsg << L"Additional info: " << GetCppExceptionInfo(exception) << std::endl;

		for (int i = 0; i < exception->ExceptionRecord->NumberParameters; ++i)
			errorMsg << L"Additional info: " << exception->ExceptionRecord->ExceptionInformation[i] << std::endl;

		lastError = errorMsg.str();

		return EXCEPTION_CONTINUE_SEARCH;
	}

	void Terminate()
	{
		MessageBoxW(NULL, lastError.c_str(), L"Textractor ERROR", MB_ICONERROR);
		std::abort();
	}

	class ProcessRecord
	{
	public:
		ProcessRecord(DWORD processId, HANDLE hostPipe) :
			hostPipe(hostPipe),
			section(OpenFileMappingW(FILE_MAP_READ, FALSE, (ITH_SECTION_ + std::to_wstring(processId)).c_str())),
			sectionMap(MapViewOfFile(section, FILE_MAP_READ, 0, 0, HOOK_SECTION_SIZE / 2)), // jichi 1/16/2015: Changed to half to hook section size
			sectionMutex(ITH_HOOKMAN_MUTEX_ + std::to_wstring(processId))
		{}

		ProcessRecord(ProcessRecord&) = delete;
		ProcessRecord& operator=(ProcessRecord) = delete;

		~ProcessRecord()
		{
			UnmapViewOfFile(sectionMap);
			CloseHandle(section);
		}

		TextHook GetHook(uint64_t addr)
		{
			if (sectionMap == nullptr) return {};
			LOCK(sectionMutex);
			auto hooks = (const TextHook*)sectionMap;
			for (int i = 0; i < MAX_HOOK; ++i)
				if (hooks[i].hp.insertion_address == addr) return hooks[i];
			return {};
		}

		HANDLE hostPipe;

	private:
		HANDLE section;
		LPVOID sectionMap;
		WinMutex sectionMutex;
	};

	ThreadEventCallback OnCreate, OnDestroy;
	ProcessEventCallback OnAttach, OnDetach;

	std::unordered_map<ThreadParam, std::shared_ptr<TextThread>> textThreadsByParams;
	std::unordered_map<DWORD, std::unique_ptr<ProcessRecord>> processRecordsByIds;

	std::recursive_mutex hostMutex;

	DWORD DUMMY;
	ThreadParam CONSOLE{ 0, -1ULL, -1ULL, -1ULL }, CLIPBOARD{ 0, 0, -1ULL, -1ULL };

	void DispatchText(ThreadParam tp, const BYTE* text, int len)
	{
		LOCK(hostMutex);
		if (textThreadsByParams[tp] == nullptr)
		{
			if (textThreadsByParams.size() > MAX_THREAD_COUNT) return Host::AddConsoleOutput(TOO_MANY_THREADS);
			OnCreate(textThreadsByParams[tp] = std::make_shared<TextThread>(tp, Host::GetHookParam(tp), Host::GetHookName(tp)));
		}
		textThreadsByParams[tp]->Push(text, len);
	}

	void RemoveThreads(std::function<bool(ThreadParam)> removeIf)
	{
		LOCK(hostMutex);
		for (auto it = textThreadsByParams.begin(); it != textThreadsByParams.end();)
			if (auto curr = it++; removeIf(curr->first))
			{
				OnDestroy(curr->second);
				textThreadsByParams.erase(curr->first);
			}
	}

	void RegisterProcess(DWORD processId, HANDLE hostPipe)
	{
		LOCK(hostMutex);
		processRecordsByIds.insert({ processId, std::make_unique<ProcessRecord>(processId, hostPipe) });
		OnAttach(processId);
	}

	void UnregisterProcess(DWORD processId)
	{
		OnDetach(processId);
		LOCK(hostMutex);
		processRecordsByIds.erase(processId);
		RemoveThreads([&](ThreadParam tp) { return tp.processId == processId; });
	}

	void CreatePipe()
	{
		std::thread([]
		{
			Host::Setup();
			SECURITY_DESCRIPTOR pipeSD = {};
			InitializeSecurityDescriptor(&pipeSD, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&pipeSD, TRUE, NULL, FALSE); // Allow non-admin processes to connect to pipe created by admin host
			SECURITY_ATTRIBUTES pipeSA = { sizeof(SECURITY_ATTRIBUTES), &pipeSD, FALSE };
			HANDLE hookPipe = CreateNamedPipeW(HOOK_PIPE, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 0, PIPE_BUFFER_SIZE, MAXDWORD, &pipeSA);
			HANDLE hostPipe = CreateNamedPipeW(HOST_PIPE, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, 0, MAXDWORD, &pipeSA);
			ConnectNamedPipe(hookPipe, nullptr);

			BYTE buffer[PIPE_BUFFER_SIZE] = {};
			DWORD bytesRead, processId;
			ReadFile(hookPipe, &processId, sizeof(processId), &bytesRead, nullptr);
			RegisterProcess(processId, hostPipe);

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
					DispatchText(tp, buffer + sizeof(tp), bytesRead - sizeof(tp));
				}
				break;
				}

			UnregisterProcess(processId);
			DisconnectNamedPipe(hookPipe);
			DisconnectNamedPipe(hostPipe);
			CloseHandle(hookPipe);
			CloseHandle(hostPipe);
		}).detach();
	}

	void StartCapturingClipboard()
	{
		std::thread([]
		{
			Host::Setup();
			for (std::wstring last; true; Sleep(50))
				if (auto text = Util::GetClipboardText())
					if (last != text.value())
						Host::GetThread(CLIPBOARD)->AddSentence(last = text.value());
		}).detach();
	}
}

namespace Host
{
	void Setup()
	{
		static std::once_flag flag;
		std::call_once(flag, []
		{
			AddVectoredExceptionHandler(FALSE, ExceptionLogger);
			SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)Terminate);
		});
		std::set_terminate(Terminate);
	}

	void Start(ProcessEventCallback onAttach, ProcessEventCallback onDetach, ThreadEventCallback onCreate, ThreadEventCallback onDestroy, TextThread::OutputCallback output)
	{
		OnAttach = onAttach; OnDetach = onDetach; OnCreate = onCreate; OnDestroy = onDestroy; TextThread::Output = output;
		RegisterProcess(CONSOLE.processId, INVALID_HANDLE_VALUE);
		OnCreate(textThreadsByParams[CONSOLE] = std::make_shared<TextThread>(CONSOLE, HookParam{}, L"Console"));
		OnCreate(textThreadsByParams[CLIPBOARD] = std::make_shared<TextThread>(CLIPBOARD, HookParam{}, L"Clipboard"));
		StartCapturingClipboard();
		CreatePipe();
	}

	void Close()
	{
		// Artikash 7/25/2018: This is only called when Textractor is closed, at which point Windows should free everything itself...right?
#ifdef _DEBUG // Check memory leaks
		LOCK(hostMutex);
		processRecordsByIds.clear();
		textThreadsByParams.clear();
#endif
	}

	bool InjectProcess(DWORD processId, DWORD timeout)
	{
		if (processId == GetCurrentProcessId()) return false;

		CloseHandle(CreateMutexW(nullptr, FALSE, (ITH_HOOKMAN_MUTEX_ + std::to_wstring(processId)).c_str()));
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			AddConsoleOutput(ALREADY_INJECTED);
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
				AddConsoleOutput(ARCHITECTURE_MISMATCH);
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

		AddConsoleOutput(INJECT_FAILED);
		return false;
	}

	void DetachProcess(DWORD processId)
	{
		LOCK(hostMutex);
		HostCommandType buffer(HOST_COMMAND_DETACH);
		WriteFile(processRecordsByIds.at(processId)->hostPipe, &buffer, sizeof(buffer), &DUMMY, nullptr);
	}

	void InsertHook(DWORD processId, HookParam hp, std::string name)
	{
		LOCK(hostMutex);
		InsertHookCmd buffer(hp, name);
		WriteFile(processRecordsByIds.at(processId)->hostPipe, &buffer, sizeof(buffer), &DUMMY, nullptr);
	}

	void RemoveHook(DWORD processId, uint64_t addr)
	{
		LOCK(hostMutex);
		RemoveHookCmd buffer(addr);
		WriteFile(processRecordsByIds.at(processId)->hostPipe, &buffer, sizeof(buffer), &DUMMY, nullptr);
	}

	HookParam GetHookParam(DWORD processId, uint64_t addr)
	{
		LOCK(hostMutex);
		return processRecordsByIds.at(processId)->GetHook(addr).hp;
	}

	std::wstring GetHookName(DWORD processId, uint64_t addr)
	{
		LOCK(hostMutex);
		return Util::StringToWideString(processRecordsByIds.at(processId)->GetHook(addr).hookName).value();
	}

	std::shared_ptr<TextThread> GetThread(ThreadParam tp)
	{
		LOCK(hostMutex);
		return textThreadsByParams[tp];
	}

	void AddConsoleOutput(std::wstring text) 
	{ 
		GetThread(CONSOLE)->AddSentence(text); 
	}
}

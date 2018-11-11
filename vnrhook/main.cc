// main.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/main.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "main.h"
#include "defs.h"
#include "text.h"
#include "MinHook.h"
#include "engine/engine.h"
#include "engine/match.h"
#include "texthook.h"
#include "util/growl.h"

std::unique_ptr<WinMutex> sectionMutex;

namespace
{
	HANDLE hSection, hookPipe;
	TextHook* hooks;
	bool running;
	int currentHook = 0, userhookCount = 0;
	DWORD DUMMY;
}

DWORD WINAPI Pipe(LPVOID)
{
	while (running)
	{
		DWORD count = 0;
		BYTE buffer[PIPE_BUFFER_SIZE] = {};
		HANDLE hostPipe = hookPipe = INVALID_HANDLE_VALUE;

		while (hookPipe == INVALID_HANDLE_VALUE || hostPipe == INVALID_HANDLE_VALUE)
		{
			if (hookPipe == INVALID_HANDLE_VALUE)
			{
				hookPipe = CreateFileW(HOOK_PIPE, GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			}
			if (hookPipe != INVALID_HANDLE_VALUE && hostPipe == INVALID_HANDLE_VALUE)
			{
				hostPipe = CreateFileW(HOST_PIPE, GENERIC_READ | FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
				DWORD mode = PIPE_READMODE_MESSAGE;
				SetNamedPipeHandleState(hostPipe, &mode, NULL, NULL);
				continue;
			}
			Sleep(50);
		}

		*(DWORD*)buffer = GetCurrentProcessId();
		WriteFile(hookPipe, buffer, sizeof(DWORD), &count, nullptr);

		ConsoleOutput(PIPE_CONNECTED);
#ifdef _WIN64
		ConsoleOutput(DISABLE_HOOKS);
#else
		Engine::Hijack();
#endif

		while (running && ReadFile(hostPipe, buffer, PIPE_BUFFER_SIZE, &count, nullptr))
			switch (*(HostCommandType*)buffer)
			{
			case HOST_COMMAND_NEW_HOOK:
			{
				auto info = *(InsertHookCmd*)buffer;
				NewHook(info.hp, info.name, 0);
			}
			break;
			case HOST_COMMAND_REMOVE_HOOK:
			{
				auto info = *(RemoveHookCmd*)buffer;
				RemoveHook(info.address);
			}
			break;
			case HOST_COMMAND_DETACH:
			{
				running = false;
			}
			break;
			}

		CloseHandle(hostPipe);
		CloseHandle(hookPipe);
	}
	FreeLibraryAndExitThread(GetModuleHandleW(ITH_DLL), 0);
	return 0;
}

void TextOutput(ThreadParam tp, BYTE* text, int len)
{
	if (len < 0) return;
	BYTE buffer[PIPE_BUFFER_SIZE] = {};
	*(ThreadParam*)buffer = tp;
	memcpy_s(buffer + sizeof(ThreadParam), sizeof(buffer) - sizeof(ThreadParam), text, len);
	WriteFile(hookPipe, buffer, sizeof(ThreadParam) + len, &DUMMY, nullptr);
}

void ConsoleOutput(LPCSTR text)
{
	ConsoleOutputNotif buffer(text);
	WriteFile(hookPipe, &buffer, sizeof(buffer), &DUMMY, nullptr);
}

void ConsoleOutput(std::string text)
{
	ConsoleOutput(text.c_str());
}

void NotifyHookRemove(uint64_t addr)
{
	HookRemovedNotif buffer(addr);
	WriteFile(hookPipe, &buffer, sizeof(buffer), &DUMMY, nullptr);
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD fdwReason, LPVOID)
{
	switch (fdwReason) 
	{
	case DLL_PROCESS_ATTACH:
	{
		sectionMutex = std::make_unique<WinMutex>(ITH_HOOKMAN_MUTEX_ + std::to_wstring(GetCurrentProcessId()));
		if (GetLastError() == ERROR_ALREADY_EXISTS) return FALSE;
		DisableThreadLibraryCalls(hModule);

		// jichi 9/25/2013: Interprocedural communication with vnrsrv.
		hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, HOOK_SECTION_SIZE, (ITH_SECTION_ + std::to_wstring(GetCurrentProcessId())).c_str());
		hooks = (TextHook*)MapViewOfFile(hSection, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, HOOK_BUFFER_SIZE);
		memset(hooks, 0, HOOK_BUFFER_SIZE);

		MH_Initialize();
		running = true;

		CreateThread(nullptr, 0, Pipe, nullptr, 0, nullptr); // Using std::thread here = deadlock
	} 
	break;
	case DLL_PROCESS_DETACH:
	{
		running = false;
		for (int i = 0; i < MAX_HOOK; ++i) if (hooks[i].hp.insertion_address) hooks[i].ClearHook();
		UnmapViewOfFile(hooks);
		MH_Uninitialize();
		CloseHandle(hSection);
	}
	break;
	}
	return TRUE;
}

//extern "C" {
void NewHook(HookParam hp, LPCSTR lpname, DWORD flag)
{
	std::string name = lpname;
	if (++currentHook < MAX_HOOK) 
	{
		if (name.empty()) name = "UserHook" + std::to_string(userhookCount++);
		ConsoleOutput(INSERTING_HOOK + name);

		// jichi 7/13/2014: This function would raise when too many hooks added
		hooks[currentHook].InitHook(hp, name.c_str(), flag);
		if (!hooks[currentHook].InsertHook()) ConsoleOutput(HOOK_FAILED);
	}
	else ConsoleOutput(TOO_MANY_HOOKS);
}

void RemoveHook(uint64_t addr)
{
	for (int i = 0; i < MAX_HOOK; i++)
		if (abs((long long)(hooks[i].hp.insertion_address - addr)) < 9) return hooks[i].ClearHook();
}

// EOF
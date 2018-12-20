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

std::unique_ptr<WinMutex> viewMutex;

namespace
{
	AutoHandle<> hookPipe = INVALID_HANDLE_VALUE, mappedFile = INVALID_HANDLE_VALUE;
	TextHook* hooks;
	bool running;
	int currentHook = 0;
	DWORD DUMMY;
}

DWORD WINAPI Pipe(LPVOID)
{
	while (running)
	{
		DWORD count = 0;
		BYTE buffer[PIPE_BUFFER_SIZE] = {};
		AutoHandle<> hostPipe = INVALID_HANDLE_VALUE;
		hookPipe = INVALID_HANDLE_VALUE;

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
				NewHook(info.hp, "UserHook", 0);
			}
			break;
			case HOST_COMMAND_DETACH:
			{
				running = false;
			}
			break;
			}
	}
	hookPipe = INVALID_HANDLE_VALUE;
	for (int i = 0; i < MAX_HOOK; ++i) if (hooks[i].address) hooks[i].Clear();
	FreeLibraryAndExitThread(GetModuleHandleW(ITH_DLL), 0);
	return 0;
}

void TextOutput(ThreadParam tp, BYTE* text, int len)
{
	if (len < 0) return;
	if (len > PIPE_BUFFER_SIZE - sizeof(ThreadParam)) len = PIPE_BUFFER_SIZE - sizeof(ThreadParam);
	BYTE buffer[PIPE_BUFFER_SIZE] = {};
	*(ThreadParam*)buffer = tp;
	memcpy(buffer + sizeof(ThreadParam), text, len);
	WriteFile(hookPipe, buffer, sizeof(ThreadParam) + len, &DUMMY, nullptr);
}

void ConsoleOutput(LPCSTR text, ...)
{
	ConsoleOutputNotif buffer;
	va_list args;
	va_start(args, text);
	vsprintf_s<MESSAGE_SIZE>(buffer.message, text, args);
	WriteFile(hookPipe, &buffer, sizeof(buffer), &DUMMY, nullptr);
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
		viewMutex = std::make_unique<WinMutex>(ITH_HOOKMAN_MUTEX_ + std::to_wstring(GetCurrentProcessId()));
		if (GetLastError() == ERROR_ALREADY_EXISTS) return FALSE;
		DisableThreadLibraryCalls(hModule);

		// jichi 9/25/2013: Interprocedural communication with vnrsrv.
		mappedFile = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, HOOK_SECTION_SIZE, (ITH_SECTION_ + std::to_wstring(GetCurrentProcessId())).c_str());
		hooks = (TextHook*)MapViewOfFile(mappedFile, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, HOOK_BUFFER_SIZE);
		memset(hooks, 0, HOOK_BUFFER_SIZE);

		MH_Initialize();
		running = true;

		CreateThread(nullptr, 0, Pipe, nullptr, 0, nullptr); // Using std::thread here = deadlock
	} 
	break;
	case DLL_PROCESS_DETACH:
	{
		running = false;
		UnmapViewOfFile(hooks);
		MH_Uninitialize();
	}
	break;
	}
	return TRUE;
}

void NewHook(HookParam hp, LPCSTR lpname, DWORD flag)
{
	if (++currentHook >= MAX_HOOK) return ConsoleOutput(TOO_MANY_HOOKS);
	if (lpname && *lpname) strcpy_s<HOOK_NAME_SIZE>(hp.name, lpname);
	ConsoleOutput(INSERTING_HOOK, hp.name);
	RemoveHook(hp.address, 0);
	if (!hooks[currentHook].Insert(hp, flag)) ConsoleOutput(HOOK_FAILED);
}

void RemoveHook(uint64_t addr, int maxOffset)
{
	for (int i = 0; i < MAX_HOOK; i++)
		if (abs((long long)(hooks[i].address - addr)) <= maxOffset) return hooks[i].Clear();
}

// EOF
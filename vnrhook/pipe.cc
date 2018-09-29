// pipe.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/pipe.cpp, rev 66
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "pipe.h"
#include "main.h"
#include "hijack/texthook.h"
#include "engine/match.h"
#include "defs.h"
#include "const.h"
#include "growl.h"

HANDLE hookPipe;

DWORD DUMMY[100];

void CreatePipe()
{
	CreateThread(nullptr, 0, [](LPVOID)
	{
		enum { STANDARD_WAIT = 50 };
		while (::running)
		{
			DWORD count = 0;
			BYTE buffer[PIPE_BUFFER_SIZE] = {};
			HANDLE hostPipe = ::hookPipe = INVALID_HANDLE_VALUE;

			while (::hookPipe == INVALID_HANDLE_VALUE || hostPipe == INVALID_HANDLE_VALUE)
			{
				if (::hookPipe == INVALID_HANDLE_VALUE)
				{
					::hookPipe = CreateFileW(ITH_TEXT_PIPE, GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
				}
				if (::hookPipe != INVALID_HANDLE_VALUE && hostPipe == INVALID_HANDLE_VALUE)
				{
					hostPipe = CreateFileW(ITH_COMMAND_PIPE, GENERIC_READ | FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
					DWORD mode = PIPE_READMODE_MESSAGE;
					SetNamedPipeHandleState(hostPipe, &mode, NULL, NULL);
				}
				Sleep(STANDARD_WAIT);
			}

			*(DWORD*)buffer = GetCurrentProcessId();
			WriteFile(::hookPipe, buffer, sizeof(DWORD), &count, nullptr);

			ConsoleOutput("Textractor: pipe connected");
#ifdef _WIN64
			ConsoleOutput("Hooks don't work on x64, only read codes work. Engine disabled.");
#else
			Engine::Hijack();
#endif

			while (::running && ReadFile(hostPipe, buffer, PIPE_BUFFER_SIZE, &count, nullptr))
				switch (*(int*)buffer)
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
					::running = false;
				}
				break;
				}

			CloseHandle(hostPipe);
		}
		FreeLibraryAndExitThread(GetModuleHandleW(ITH_DLL), 0);
		return (DWORD)0;
	}, nullptr, 0, nullptr);
}

void ConsoleOutput(LPCSTR text)
{
	auto info = ConsoleOutputNotif(text);
	WriteFile(::hookPipe, &info, strlen(text) + sizeof(info), DUMMY, nullptr);
}

void NotifyHookRemove(uint64_t addr)
{
	auto info = HookRemovedNotif(addr);
	WriteFile(::hookPipe, &info, sizeof(info), DUMMY, nullptr);
}

// EOF

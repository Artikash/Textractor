// pipe.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/pipe.cpp, rev 66
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "src/hijack/texthook.h"
#include "src/engine/match.h"
#include "src/util/util.h"
#include "src/main.h"
#include "include/defs.h"
#include "src/util/growl.h"
#include "ithsys/ithsys.h"
#include <cstdio> // for swprintf

HANDLE hookPipe;
extern HMODULE currentModule;

DWORD WINAPI PipeManager(LPVOID unused)
{
	enum { STANDARD_WAIT = 50 };
	while (::running)
	{
		DWORD count;
		BYTE buffer[PIPE_BUFFER_SIZE];
		HANDLE hostPipe = ::hookPipe = INVALID_HANDLE_VALUE,
			pipeAcquisitionMutex = CreateMutexW(nullptr, TRUE, ITH_GRANTPIPE_MUTEX);

		while (::hookPipe == INVALID_HANDLE_VALUE || hostPipe == INVALID_HANDLE_VALUE)
		{
			Sleep(STANDARD_WAIT);
			if (::hookPipe == INVALID_HANDLE_VALUE)
			{
				::hookPipe = CreateFileW(ITH_TEXT_PIPE, GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			}
			if (hostPipe == INVALID_HANDLE_VALUE)
			{
				hostPipe = CreateFileW(ITH_COMMAND_PIPE, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			}
		}

		*(DWORD*)buffer = GetCurrentProcessId();
		WriteFile(::hookPipe, buffer, sizeof(DWORD), &count, nullptr);

		ReleaseMutex(pipeAcquisitionMutex);
		CloseHandle(pipeAcquisitionMutex);

		ConsoleOutput("vnrcli:WaitForPipe: pipe connected");
		Engine::Hijack();

		while (::running)
		{
			if (!ReadFile(hostPipe, buffer, PIPE_BUFFER_SIZE / 2, &count, nullptr)) // Artikash 5/21/2018: why / 2? wchar_t?
			{
				break;
			}
			DWORD command = *(DWORD*)buffer;
			switch (command)
			{
			case HOST_COMMAND_NEW_HOOK:
				buffer[count] = 0;
				NewHook(*(HookParam *)(buffer + sizeof(DWORD)), // Hook parameter
					(LPSTR)(buffer + 4 + sizeof(HookParam)), // Hook name
					0
				);
				break;
			case HOST_COMMAND_REMOVE_HOOK:
			{
				TextHook *in = hookman;
				for (int i = 0; i < currentHook; in++)
				{
					if (in->Address()) i++;
					if (in->Address() == *(DWORD *)(buffer + sizeof(DWORD))) // Hook address
					{
						break;
					}
				}
				if (in->Address())
				{
					in->ClearHook();
				}
			}
			break;
			case HOST_COMMAND_DETACH:
				::running = false;
				break;
			}
		}
		CloseHandle(::hookPipe);
		CloseHandle(hostPipe);
	}
	FreeLibraryAndExitThread(::currentModule, 0);
	return 0;
}

void ConsoleOutput(LPCSTR text)
{	
	BYTE buffer[PIPE_BUFFER_SIZE];
	*(DWORD*)buffer = HOST_NOTIFICATION;
	*(DWORD*)(buffer + sizeof(DWORD)) = HOST_NOTIFICATION_TEXT;
	strcpy((char*)buffer + sizeof(DWORD) * 2, text);
	DWORD unused;
	WriteFile(::hookPipe, buffer, strlen(text) + sizeof(DWORD) * 2, &unused, nullptr);
}

void NotifyHookInsert(HookParam hp, LPCSTR name)
{
    BYTE buffer[PIPE_BUFFER_SIZE];
    *(DWORD*)buffer = HOST_NOTIFICATION;
    *(DWORD*)(buffer + sizeof(DWORD)) = HOST_NOTIFICATION_NEWHOOK;
    *(HookParam*)(buffer + sizeof(DWORD) * 2) = hp;
	strcpy((char*)buffer + sizeof(DWORD) * 2 + sizeof(HookParam), name);
	DWORD unused;
	WriteFile(::hookPipe, buffer, strlen(name) + sizeof(DWORD) * 2 + sizeof(HookParam), &unused, nullptr);
	return;
}

void NotifyHookRemove(DWORD addr)
{
	BYTE buffer[sizeof(DWORD) * 3];
	*(DWORD*)buffer = HOST_NOTIFICATION;
	*(DWORD*)(buffer + sizeof(DWORD)) = HOST_NOTIFICATION_RMVHOOK;
	*(DWORD*)(buffer + sizeof(DWORD) * 2) = addr;
	DWORD unused;
	WriteFile(::hookPipe, buffer, sizeof(DWORD) * 3, &unused, nullptr);
	return;
}

// EOF

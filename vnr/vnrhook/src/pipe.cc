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
	enum { STANDARD_WAIT = 1000 };
	while (::running)
	{
		DWORD count;
		BYTE* buffer = new BYTE[PIPE_BUFFER_SIZE];
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
		WriteFile(::hookPipe, buffer, sizeof(DWORD), nullptr, nullptr);

		for (int i = 0, count = 0; count < ::currentHook; i++)
		{
			if (hookman[i].RecoverHook()) // jichi 9/27/2013: This is the place where built-in hooks like TextOutA are inserted
			{
				count++;
			}
		}

		ReleaseMutex(pipeAcquisitionMutex);
		CloseHandle(pipeAcquisitionMutex);

		::live = true;
		Engine::hijack();
		ConsoleOutput("vnrcli:WaitForPipe: pipe connected");

		while (::running)
		{
			Sleep(STANDARD_WAIT);
			if (!ReadFile(hostPipe, buffer, PIPE_BUFFER_SIZE / 2, &count, nullptr)) // Artikash 5/21/2018: why / 2? wchar_t?
			{
				break;
			}
			DWORD command = *(DWORD*)buffer;
			switch (command)
			{
			case HOST_COMMAND_NEW_HOOK:
				buffer[count] = 0;
				NewHook(*(HookParam *)(buffer + 4), (LPSTR)(buffer + 4 + sizeof(HookParam)), 0);
				break;
			case HOST_COMMAND_REMOVE_HOOK:
			{
				DWORD removalAddress = *(DWORD *)(buffer + 4);
				HANDLE hookRemovalEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, ITH_REMOVEHOOK_EVENT);

				TextHook *in = hookman;
				for (int i = 0; i < currentHook; in++)
				{
					if (in->Address()) i++;
					if (in->Address() == removalAddress)
					{
						break;
					}
				}
				if (in->Address())
				{
					in->ClearHook();
				}

				SetEvent(hookRemovalEvent);
				CloseHandle(hookRemovalEvent);
			}
			break;
			case HOST_COMMAND_DETACH:
				::running = false;
				break;
			}
		}

		::live = false;
		for (int i = 0, count = 0; count < ::currentHook; i++)
		{
			if (hookman[i].RemoveHook())
			{
				count++;
			}
		}
		CloseHandle(::hookPipe);
		CloseHandle(hostPipe);
	}
	FreeLibraryAndExitThread(::currentModule, 0);
	return 0;
}

void ConsoleOutput(LPCSTR text)
{ // jichi 12/25/2013: Rewrite the implementation
	if (!::live)
	{
		return;
	}
		
	DWORD textSize = strlen(text) + 1;
	DWORD dataSize = textSize + 8;
	BYTE *buffer = new BYTE[dataSize];
	*(DWORD*)buffer = HOST_NOTIFICATION; //cmd
	*(DWORD*)(buffer + 4) = HOST_NOTIFICATION_TEXT; //console
	memcpy(buffer + 8, text, textSize);
	WriteFile(::hookPipe, buffer, dataSize, nullptr, nullptr);
}

// Artikash 7/3/2018: TODO: Finish using this in vnrhost instead of section to deliver hook name
void NotifyHookInsert(DWORD addr, LPCSTR name)
{
	if (!::live)
	{
		return;
	}
    BYTE buffer[PIPE_BUFFER_SIZE];
    *(DWORD*)buffer = HOST_NOTIFICATION;
    *(DWORD*)(buffer + 4) = HOST_NOTIFICATION_NEWHOOK;
    *(DWORD*)(buffer + 8) = addr;
	strcpy((char*)buffer + 12, name);
	WriteFile(::hookPipe, buffer, strlen(name) + 12, nullptr, nullptr);
	return;
}

// EOF

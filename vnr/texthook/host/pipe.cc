// pipe.cc
// 8/24/2013 jichi
// Branch IHF/pipe.cpp, rev 93
// 8/24/2013 TODO: Clean up this file

#include "host.h"
#include "hookman.h"
#include "vnrhook/include/defs.h"
#include "vnrhook/include/const.h"
#include <stdio.h>
#include "growl.h"
#include <atlbase.h>

extern HookManager* man;

struct Pipes
{
	HANDLE hookPipe;
	HANDLE hostPipe;
};

DWORD WINAPI TextReceiver(LPVOID lpThreadParameter);

void CreateNewPipe()
{
	CloseHandle(CreateThread(nullptr, 0, TextReceiver, new Pipes
		{
			CreateNamedPipeW(ITH_TEXT_PIPE, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, MAXDWORD, NULL),
			CreateNamedPipeW(ITH_COMMAND_PIPE, PIPE_ACCESS_OUTBOUND, 0, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, MAXDWORD, NULL)
		},
	0, nullptr));
}

DWORD WINAPI TextReceiver(LPVOID lpThreadParameter)
{
	Pipes* pipes = (Pipes*)lpThreadParameter;
	ConnectNamedPipe(pipes->hookPipe, nullptr);

	BYTE buffer[PIPE_BUFFER_SIZE] = {};
	DWORD bytesRead, processId;

	// Artikash 5/20/2018: Shouldn't Windows automatically close the handles when the host process stops running?
	//if (!::running) {
	//  NtClose(hookPipe);
	//  return 0;
	//}

	ReadFile(pipes->hookPipe, &processId, sizeof(processId), &bytesRead, nullptr);
	man->RegisterProcess(processId, pipes->hostPipe);

	// jichi 9/27/2013: why recursion?
	// Artikash 5/20/2018: To create a new pipe for another process
	CreateNewPipe();

	while (true)
	{
		if (!ReadFile(pipes->hookPipe, buffer, PIPE_BUFFER_SIZE, &bytesRead, nullptr)) break;

		buffer[bytesRead] = 0;
		buffer[bytesRead + 1] = 0;

		if (*(DWORD*)buffer == HOST_NOTIFICATION)
		{
			USES_CONVERSION;
			switch (*(DWORD*)(buffer + 4)) // Artikash 7/17/2018: Notification type
			{
			case HOST_NOTIFICATION_NEWHOOK:	// Artikash 7/18/2018: Useless for now, but could be used to implement smth later
				break;
			case HOST_NOTIFICATION_TEXT:
				man->AddConsoleOutput(A2W((LPCSTR)(buffer + sizeof(DWORD) * 2))); // Text
				break;
			}
		}
		else
		{
			// jichi 9/28/2013: Debug raw data
			//ITH_DEBUG_DWORD9(RecvLen - 0xc,
			//    buffer[0xc], buffer[0xd], buffer[0xe], buffer[0xf],
			//    buffer[0x10], buffer[0x11], buffer[0x12], buffer[0x13]);
			man->DispatchText(processId, buffer + HEADER_SIZE, 
				*(DWORD*)buffer, // Hook address
				*(DWORD*)(buffer + sizeof(DWORD)), // Return address
				*(DWORD*)(buffer + sizeof(DWORD) * 2), // Split
				bytesRead - HEADER_SIZE
			);
		}
	}

	DisconnectNamedPipe(pipes->hookPipe);
	DisconnectNamedPipe(pipes->hostPipe);
	man->UnRegisterProcess(processId);
	CloseHandle(pipes->hookPipe);
	CloseHandle(pipes->hostPipe);

	delete pipes;

	return 0;
}

// EOF

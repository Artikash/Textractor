// pipe.cc
// 8/24/2013 jichi
// Branch IHF/pipe.cpp, rev 93

#include "pipe.h"
#include "host.h"
#include "../vnrhook/include/defs.h"
#include "../vnrhook/include/const.h"
#include <atlbase.h>

struct Pipes
{
	HANDLE hookPipe;
	HANDLE hostPipe;
};

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
	ReadFile(pipes->hookPipe, &processId, sizeof(processId), &bytesRead, nullptr);
	RegisterProcess(processId, pipes->hostPipe);

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
				Host::AddConsoleOutput(A2W((LPCSTR)(buffer + sizeof(DWORD) * 2))); // Text
				break;
			}
		}
		else
		{
			DispatchText(processId,
				*(DWORD*)buffer, // Hook address
				*(DWORD*)(buffer + sizeof(DWORD)), // Return address
				*(DWORD*)(buffer + sizeof(DWORD) * 2), // Split
				buffer + HEADER_SIZE, // Data
				bytesRead - HEADER_SIZE // Data size
			);
		}
	}

	DisconnectNamedPipe(pipes->hookPipe);
	DisconnectNamedPipe(pipes->hostPipe);
	UnregisterProcess(processId);
	CloseHandle(pipes->hookPipe);
	CloseHandle(pipes->hostPipe);
	delete pipes;
	return 0;
}

// EOF

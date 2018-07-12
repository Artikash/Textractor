// pipe.cc
// 8/24/2013 jichi
// Branch IHF/pipe.cpp, rev 93
// 8/24/2013 TODO: Clean up this file

#include "host_p.h"
#include "hookman.h"
#include "vnrhook/include/defs.h"
#include "vnrhook/include/const.h"
#include "ithsys/ithsys.h"
#include <stdio.h>
#include "growl.h"
#include <atlbase.h>
//#include "CommandQueue.h"
//#include <QtCore/QDebug>

#define DEBUG "vnrhost/pipe.cc"

CRITICAL_SECTION detachCs; // jichi 9/27/2013: also used in main
//HANDLE hDetachEvent;
extern HANDLE pipeExistsEvent;

struct Pipes
{
	HANDLE hookPipe;
	HANDLE hostPipe;
};

void CreateNewPipe()
{
	CreateThread(nullptr, 0, TextReceiver, new Pipes
		{
			CreateNamedPipeW(ITH_TEXT_PIPE, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, MAXDWORD, NULL),
			CreateNamedPipeW(ITH_COMMAND_PIPE, PIPE_ACCESS_OUTBOUND, 0, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, MAXDWORD, NULL)
		},
	0, nullptr);
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

	while (::running)
	{
		if (!ReadFile(pipes->hookPipe, buffer, PIPE_BUFFER_SIZE, &bytesRead, nullptr))
		{
			break;
		}

		enum { DATA_OFFSET = 0xc }; // jichi 10/27/2013: Seem to be the data offset in the pipe

		if (bytesRead < DATA_OFFSET)
		{
			break;
		}

		union { DWORD retn; DWORD commandType; };
		DWORD hook = *(DWORD *)buffer;
		retn = *(DWORD *)(buffer + 4);
		DWORD split = *(DWORD *)(buffer + 8);

		buffer[bytesRead] = 0;
		buffer[bytesRead + 1] = 0;

		if (hook == HOST_NOTIFICATION)
		{
			switch (commandType) 
			{
			case HOST_NOTIFICATION_NEWHOOK: // Artikash 5/30/2018: Useless for now, but could be handy to implement something later
				break;
			case HOST_NOTIFICATION_TEXT:
				USES_CONVERSION;
				man->AddConsoleOutput(A2W((LPCSTR)(buffer + 8)));
				break;
			}
		}
		else
		{
			// jichi 9/28/2013: Debug raw data
			//ITH_DEBUG_DWORD9(RecvLen - 0xc,
			//    buffer[0xc], buffer[0xd], buffer[0xe], buffer[0xf],
			//    buffer[0x10], buffer[0x11], buffer[0x12], buffer[0x13]);

			const BYTE *data = buffer + DATA_OFFSET; // th
			int dataLength = bytesRead - DATA_OFFSET;
			man->DispatchText(processId, data, hook, retn, split, dataLength);
		}
	}

	EnterCriticalSection(&detachCs);

	DisconnectNamedPipe(pipes->hookPipe);
	DisconnectNamedPipe(pipes->hostPipe);
	man->UnRegisterProcess(processId);

	LeaveCriticalSection(&detachCs);
	delete pipes;

	return 0;
}

// EOF

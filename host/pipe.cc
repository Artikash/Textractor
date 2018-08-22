// pipe.cc
// 8/24/2013 jichi
// Branch IHF/pipe.cpp, rev 93

#include "pipe.h"
#include "host.h"
#include "../vnrhook/include/defs.h"
#include "../vnrhook/include/const.h"
#include <atlbase.h>

void CreateNewPipe()
{
	std::thread([]()
	{
		HANDLE hookPipe = CreateNamedPipeW(ITH_TEXT_PIPE, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, MAXDWORD, NULL);
		HANDLE hostPipe = CreateNamedPipeW(ITH_COMMAND_PIPE, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, MAXDWORD, NULL);
		ConnectNamedPipe(hookPipe, nullptr);

		// jichi 9/27/2013: why recursion?
		// Artikash 5/20/2018: Easy way to create a new pipe for another process
		CreateNewPipe();

		BYTE buffer[PIPE_BUFFER_SIZE + 1] = {};
		DWORD bytesRead, processId;
		ReadFile(hookPipe, &processId, sizeof(processId), &bytesRead, nullptr);
		RegisterProcess(processId, hostPipe);

		while (ReadFile(hookPipe, buffer, PIPE_BUFFER_SIZE, &bytesRead, nullptr))
		{
			buffer[bytesRead] = 0;
			buffer[bytesRead + 1] = 0;

			if (*(DWORD*)buffer == HOST_NOTIFICATION)
				switch (*(DWORD*)(buffer + sizeof(DWORD))) // Artikash 7/17/2018: Notification type
				{
				case HOST_NOTIFICATION_NEWHOOK:	// Artikash 7/18/2018: Useless for now, but could be used to implement smth later
					break;
				case HOST_NOTIFICATION_RMVHOOK:
					RemoveThreads([](auto one, auto two) { return one.pid == two.pid && one.hook == two.hook; },
						{ processId, *(DWORD*)(buffer + sizeof(DWORD) * 2) }); // Address
					break;
				case HOST_NOTIFICATION_TEXT:
					USES_CONVERSION;
					Host::AddConsoleOutput(A2W((LPCSTR)(buffer + sizeof(DWORD) * 2))); // Text
					break;
				}
			else DispatchText(
				{ 
					processId,
					*(DWORD*)buffer, // Hook address
					*(DWORD*)(buffer + sizeof(DWORD)), // Return address
					*(DWORD*)(buffer + sizeof(DWORD) * 2) // Split
				},
				buffer + HEADER_SIZE, // Data
				bytesRead - HEADER_SIZE // Data size
			);
		}

		DisconnectNamedPipe(hookPipe);
		DisconnectNamedPipe(hostPipe);
		UnregisterProcess(processId);
		CloseHandle(hookPipe);
		CloseHandle(hostPipe);
	}).detach();
}

// EOF

// pipe.cc
// 8/24/2013 jichi
// Branch IHF/pipe.cpp, rev 93

#include "pipe.h"
#include "host.h"
#include "defs.h"
#include "const.h"

void CreatePipe()
{
	std::thread([]()
	{
		HANDLE hookPipe = CreateNamedPipeW(ITH_TEXT_PIPE, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, MAXDWORD, NULL);
		HANDLE hostPipe = CreateNamedPipeW(ITH_COMMAND_PIPE, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, MAXDWORD, NULL);
		ConnectNamedPipe(hookPipe, nullptr);

		// jichi 9/27/2013: why recursion?
		// Artikash 5/20/2018: Easy way to create a new pipe for another process
		CreatePipe();

		BYTE buffer[PIPE_BUFFER_SIZE + 1] = {};
		DWORD bytesRead, processId;
		ReadFile(hookPipe, &processId, sizeof(processId), &bytesRead, nullptr);
		RegisterProcess(processId, hostPipe);

		while (ReadFile(hookPipe, buffer, PIPE_BUFFER_SIZE, &bytesRead, nullptr))
			switch (*(int*)buffer)
			{
			//case HOST_NOTIFICATION_NEWHOOK:	// Artikash 7/18/2018: Useless for now, but could be used to implement smth later
			//break;
			case HOST_NOTIFICATION_RMVHOOK:
			{
				auto info = *(HookRemovedNotif*)buffer;
				RemoveThreads([](auto one, auto two) { return one.pid == two.pid && one.hook == two.hook; }, { processId, info.address });
			}
			break;
			case HOST_NOTIFICATION_TEXT:
			{
				auto info = *(ConsoleOutputNotif*)buffer;
				USES_CONVERSION;
				Host::AddConsoleOutput(A2W(info.message));
			}
			break;
			default:
			{
				ThreadParam tp = *(ThreadParam*)buffer;
				DispatchText(tp, buffer + sizeof(tp), bytesRead - sizeof(tp));
			}
			break;
			}

		DisconnectNamedPipe(hookPipe);
		DisconnectNamedPipe(hostPipe);
		UnregisterProcess(processId);
		CloseHandle(hookPipe);
		CloseHandle(hostPipe);
	}).detach();
}

// EOF

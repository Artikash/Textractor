#include "match.h"
#include "engine.h"
#include "main.h"
#include "native/pchooks.h"

extern const char* HIJACK_ERROR;

uintptr_t processStartAddress, processStopAddress;

namespace Engine
{
	WCHAR* processName, // cached
		processPath[MAX_PATH]; // cached

	bool UnsafeDetermineEngineType();

	// jichi 10/21/2014: Return whether found the game engine
	bool DetermineEngineType()
	{
		// jichi 9/27/2013: disable game engine for debugging use
		bool found = false;
#ifndef ITH_DISABLE_ENGINE
		__try { found = UnsafeDetermineEngineType(); }
		__except (EXCEPTION_EXECUTE_HANDLER) { ConsoleOutput(HIJACK_ERROR); }
#endif // ITH_DISABLE_ENGINE
		if (!found) { // jichi 10/2/2013: Only enable it if no game engine is detected
			PcHooks::hookOtherPcFunctions();
		} //else
		//  ConsoleOutput("vnreng: found game engine, IGNORE non gui hooks");
		return found;
	}

	DWORD InsertDynamicHook(LPVOID addr, DWORD frame, DWORD stack)
	{
		return trigger_fun ? !trigger_fun(addr, frame, stack) : 0;
	}

	void Hijack()
	{
		static bool hijacked = false;
		if (hijacked) return;
		GetModuleFileNameW(nullptr, processPath, MAX_PATH);
		processName = wcsrchr(processPath, L'\\') + 1;

		processStartAddress = processStopAddress = (uintptr_t)GetModuleHandleW(nullptr);
		MEMORY_BASIC_INFORMATION info;
		do
		{
			VirtualQuery((void*)processStopAddress, &info, sizeof(info));
			processStopAddress = (uintptr_t)info.BaseAddress + info.RegionSize;
		} while (info.Protect > PAGE_NOACCESS);
		processStopAddress -= info.RegionSize;

		DetermineEngineType();
		hijacked = true;
		ConsoleOutput("Textractor: finished hijacking process located from 0x%p to 0x%p", processStartAddress, processStopAddress);
	}
}

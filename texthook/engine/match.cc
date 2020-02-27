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

	char configFileData[1000];

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
		static auto _ = []
		{
			GetModuleFileNameW(nullptr, processPath, MAX_PATH);
			processName = wcsrchr(processPath, L'\\') + 1;
			wchar_t configFilename[MAX_PATH + sizeof(L"TextractorConfig.txt")];
			wcsncpy_s(configFilename, processPath, MAX_PATH - 1);
			wcscpy_s(wcsrchr(configFilename, L'\\') + 1, sizeof(L"TextractorConfig.txt"), L"TextractorConfig.txt");
			if (AutoHandle<> configFile = CreateFileW(configFilename, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL))
			{
				if (ReadFile(configFile, configFileData, sizeof(configFileData) - 1, DUMMY, nullptr)) ConsoleOutput("Textractor: game configuration loaded");
				if (strncmp(configFileData, "Engine:", 7) == 0)
				{
					if (loadedConfig = strchr(configFileData, '\n')) *(char*)loadedConfig++ = 0;
					ConsoleOutput("Textractor: Engine = %s", requestedEngine = configFileData + 7);
				}
				else loadedConfig = configFileData;
			}

			processStartAddress = processStopAddress = (uintptr_t)GetModuleHandleW(nullptr);
			MEMORY_BASIC_INFORMATION info;
			do
			{
				VirtualQuery((void*)processStopAddress, &info, sizeof(info));
				processStopAddress = (uintptr_t)info.BaseAddress + info.RegionSize;
			} while (info.Protect > PAGE_NOACCESS);
			processStopAddress -= info.RegionSize;
			spDefault.minAddress = processStartAddress;
			spDefault.maxAddress = processStopAddress;
			ConsoleOutput("Textractor: hijacking process located from 0x%p to 0x%p", processStartAddress, processStopAddress);

			DetermineEngineType();
			return NULL;
		}();
	}
}

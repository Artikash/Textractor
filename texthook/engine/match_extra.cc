#include "match.h"
#include "engine.h"
#include "main.h"
#include "defs.h"
#include "native/pchooks.h"

extern const char* HIJACK_ERROR;

uintptr_t processStartAddress, processStopAddress;

namespace Engine
{
	WCHAR* processName, // cached
		processPath[MAX_PATH]; // cached

	char configFileData[1000]{};

	bool UnsafeDetermineEngineType();
	 

	void Hijack()
	{
		static auto _ = ([]
			{
				GetModuleFileNameW(nullptr, processPath, MAX_PATH);
				processName = wcsrchr(processPath, L'\\') + 1;
				wchar_t configFilename[MAX_PATH + std::size(GAME_CONFIG_FILE)];
				wcsncpy_s(configFilename, processPath, MAX_PATH - 1);
				wcscpy_s(wcsrchr(configFilename, L'\\') + 1, std::size(GAME_CONFIG_FILE), GAME_CONFIG_FILE);
				if (AutoHandle<> configFile = CreateFileW(configFilename, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL))
				{
					ReadFile(configFile, configFileData, sizeof(configFileData) - 1, DUMMY, nullptr);
					if (strncmp(configFileData, "Engine:", 7) == 0)
					{
						if (loadedConfig = strchr(configFileData, '\n')) *(char*)loadedConfig++ = 0;
						ConsoleOutput("Textractor: Engine = %s", requestedEngine = configFileData + 7);
					}
					else loadedConfig = configFileData;
					if ((loadedConfig && !*loadedConfig) || strstr(configFileData, "https://")) loadedConfig = nullptr;
					else ConsoleOutput("Textractor: game configuration loaded");
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

				UnsafeDetermineEngineType();
				if (processStartAddress + 0x40000 > processStopAddress) ConsoleOutput("Textractor: WARNING injected process is very small, possibly a dummy!");
			}(), 0);
	}
	 
}

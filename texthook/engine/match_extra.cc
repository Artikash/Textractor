#include "match.h"
#include "engine.h"
#include "main.h"
#include "defs.h"
#include "native/pchooks.h"

extern const char* HIJACK_ERROR;

uintptr_t processStartAddress, processStopAddress;

namespace Engine
{ 
	bool UnsafeDetermineEngineType(); 

	void Hijack()
	{
		static auto _ = ([]
			{ 
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

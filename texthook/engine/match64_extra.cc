#include "match.h"
#include "main.h"
#include "texthook.h"
#include "native/pchooks.h"
#include "mono/monoobject.h"
#include "mono/funcinfo.h"
#include "engine.h"
#include "util.h"

namespace Engine
{ 
	 

	bool InsertArtemis64Hook()
	{
		const BYTE BYTES[] = {
			0x48,0x89,0x5C,0x24,0x20,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xec,0x60
			//__int64 __fastcall sub_14017A760(__int64 a1, char *a2, char **a3)
			//FLIP FLOP IO
		};
		auto addrs = Util::SearchMemory(BYTES, sizeof(BYTES), PAGE_EXECUTE_READ, processStartAddress, processStopAddress);  
		for (auto addr : addrs) {
			char info[1000] = {};
			sprintf(info, "Textractor: InsertArtemis64Hook %08x", addr);
			ConsoleOutput(info);
			HookParam hp = {};
			hp.address = addr;
			hp.type = USING_UTF8 | USING_STRING;
			hp.offset = -0x24 - 4;//rdx 
			NewHook(hp, "Artemis64");
			return true;
		}
		
		ConsoleOutput("Textractor: InsertArtemis64Hook failed");
		return false;
	}
	bool UnsafeDetermineEngineType()
	{ 
		if (Util::CheckFile(L"*.pfs")) {
			InsertArtemis64Hook();
			return true;
		} 
		return false;
	}
}
#include "main.h"
#include "native/pchooks.h"
#include "match.h"

namespace Engine
{
	void Hijack()
	{
		static bool hijacked = false;
		if (hijacked) return;
		hijacked = true;
		__try
		{
			PcHooks::hookGDIFunctions();
			PcHooks::hookGDIPlusFunctions();
			PcHooks::hookOtherPcFunctions();
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { ConsoleOutput("Textractor: Hijack ERROR"); }
	}
}
#include "match.h"
#include "main.h"
#include "text.h"
#include "native/pchooks.h"

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
		__except (EXCEPTION_EXECUTE_HANDLER) { ConsoleOutput(HIJACK_ERROR); }
	}
}
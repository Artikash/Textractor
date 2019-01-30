#include "match.h"
#include "main.h"
#include "text.h"
#include "native/pchooks.h"

namespace Engine
{
	void HookDirectX()
	{

		for (std::wstring DXVersion : { L"d3dx9", L"d3dx10" })
			if (HMODULE module = GetModuleHandleW(DXVersion.c_str())) PcHooks::hookD3DXFunctions(module);
			else for (int i = 0; i < 50; ++i)
				if (HMODULE module = GetModuleHandleW((DXVersion + L"_" + std::to_wstring(i)).c_str())) PcHooks::hookD3DXFunctions(module);
	}
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
			HookDirectX();
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { ConsoleOutput(HIJACK_ERROR); }
	}
}
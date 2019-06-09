#include "match.h"
#include "main.h"
#include "native/pchooks.h"
#include "engine.h"
#include "util.h"

namespace Engine
{
	/** Artikash 6/7/2019
*   PPSSPP JIT code has pointers, but they are all added to an offset before being used.
	Find that offset and report it to user so they can search for hooks properly.
	To find the offset, find a page of mapped memory with size 0x1f00000, read and write permissions, take its address and subtract 0x8000000.
	The above is useful for emulating PSP hardware, so unlikely to change between versions.
*/
	bool FindPPSSPP()
	{
		bool found = false;
		SYSTEM_INFO systemInfo;
		GetNativeSystemInfo(&systemInfo);
		for (BYTE* probe = NULL; probe < systemInfo.lpMaximumApplicationAddress;)
		{
			MEMORY_BASIC_INFORMATION info;
			if (!VirtualQuery(probe, &info, sizeof(info)))
			{
				probe += systemInfo.dwPageSize;
			}
			else
			{
				if (info.RegionSize == 0x1f00000 && info.Protect == PAGE_READWRITE && info.Type == MEM_MAPPED)
				{
					found = true;
					ConsoleOutput("Textractor: PPSSPP memory found: use pattern 79 10 41 C7 and pattern offset 0 and string offset %p to search for hooks", probe - 0x8000000);
				}
				probe += info.RegionSize;
			}
		}
		return found;
	}

	bool UnsafeDetermineEngineType()
	{
		for (std::wstring DXVersion : { L"d3dx9", L"d3dx10" })
			if (HMODULE module = GetModuleHandleW(DXVersion.c_str())) PcHooks::hookD3DXFunctions(module);
			else for (int i = 0; i < 50; ++i)
				if (HMODULE module = GetModuleHandleW((DXVersion + L"_" + std::to_wstring(i)).c_str())) PcHooks::hookD3DXFunctions(module);

		if (Util::CheckFile(L"PPSSPP*.exe") && FindPPSSPP()) return true;

		PcHooks::hookGDIFunctions();
		PcHooks::hookGDIPlusFunctions();
		return false;
	}
}
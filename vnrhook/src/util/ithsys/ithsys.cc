// ithsys.cc
// 8/21/2013 jichi
// Branch: ITH_SYS/SYS.cpp, rev 126
//
// 8/24/2013 TODO:
// - Clean up the code
// - Move my old create remote thread for ITH2 here

#include "ithsys/ithsys.h"

// - Global variables -

// jichi 6/12/2015: https://en.wikipedia.org/wiki/Shift_JIS
// Leading table for SHIFT-JIS encoding
BYTE LeadByteTable[0x100] = {
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1
};

// - API functions -

extern "C" {
/**
*  Return the address of the first matched pattern.
*  Artikash 7/14/2018: changed implementation, hopefully it behaves the same
*  Return 0 if failed. The return result is ambiguous if the pattern address is 0.
*
*  @param  startAddress  search start address
*  @param  range  search range
*  @param  pattern  array of bytes to match
*  @param  patternSize  size of the pattern array
*  @return  relative offset from the startAddress
*/
DWORD SearchPattern(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length)
{
	// Artikash 7/14/2018: not sure, but I think this could throw read access violation if I dont subtract search_length
	for (int i = 0; i < base_length - search_length; ++i)
		for (int j = 0; j <= search_length; ++j)
			if (j == search_length) return i; // not sure about this algorithm...
			else if (*((BYTE*)base + i + j) != *((BYTE*)search + j) && *((BYTE*)search + j) != 0x11) break; // 0x11 = wildcard
		//if (memcmp((void*)(base + i), search, search_length) == 0)
			//return i;

	return 0;
}

DWORD IthGetMemoryRange(LPCVOID mem, DWORD *base, DWORD *size)
{
  DWORD r;
  MEMORY_BASIC_INFORMATION info;
  NtQueryVirtualMemory(NtCurrentProcess(), const_cast<LPVOID>(mem), MemoryBasicInformation, &info, sizeof(info), &r);
  if (base)
    *base = (DWORD)info.BaseAddress;
  if (size)
    *size = info.RegionSize;
  return (info.Type&PAGE_NOACCESS) == 0;
}

inline DWORD GetHash(LPSTR str)
{
	DWORD hash = 0;
	//for (; *str; str++)
	while (*str)
		hash = ((hash >> 7) | (hash << 25)) + *str++;
	return hash;
}

} // extern "C"

// EOF
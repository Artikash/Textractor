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
		if (memcmp((void*)(base + i), search, search_length) == 0)
			return i;

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

//Query module export table. Return function address if found.
//Similar to GetProcAddress
DWORD GetExportAddress(DWORD hModule,DWORD hash)
{
  IMAGE_DOS_HEADER *DosHdr;
  IMAGE_NT_HEADERS *NtHdr;
  IMAGE_EXPORT_DIRECTORY *ExtDir;
  UINT uj;
  char* pcExportAddr,*pcFuncPtr,*pcBuffer;
  DWORD dwReadAddr,dwFuncAddr,dwFuncName;
  WORD wOrd;
  DosHdr = (IMAGE_DOS_HEADER*)hModule;
  if (IMAGE_DOS_SIGNATURE==DosHdr->e_magic) {
    dwReadAddr=hModule+DosHdr->e_lfanew;
    NtHdr=(IMAGE_NT_HEADERS*)dwReadAddr;
    if (IMAGE_NT_SIGNATURE == NtHdr->Signature) {
      pcExportAddr = (char*)((DWORD)hModule+
          (DWORD)NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
      if (!pcExportAddr)
        return 0;
      ExtDir = (IMAGE_EXPORT_DIRECTORY*)pcExportAddr;
      pcExportAddr = (char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfNames);

      for (uj = 0; uj < ExtDir->NumberOfNames; uj++) {
        dwFuncName = *(DWORD *)pcExportAddr;
        pcBuffer = (char*)((DWORD)hModule+dwFuncName);
        if (GetHash(pcBuffer) == hash) {
          pcFuncPtr = (char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfNameOrdinals+(uj*sizeof(WORD)));
          wOrd = *(WORD*)pcFuncPtr;
          pcFuncPtr = (char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfFunctions+(wOrd*sizeof(DWORD)));
          dwFuncAddr = *(DWORD *)pcFuncPtr;
          return hModule+dwFuncAddr;
        }
        pcExportAddr += sizeof(DWORD);
      }
    }
  }
  return 0;
}

} // extern "C"

// EOF
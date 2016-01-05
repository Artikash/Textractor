// ntinspect.cc
// 4/20/2014 jichi
#include "ntdll/ntdll.h"
#include "ntinspect/ntinspect.h"

// https://social.msdn.microsoft.com/Forums/vstudio/en-US/4cb11cd3-8ce0-49d7-9dda-d62e9ae0180b/how-to-get-current-module-handle?forum=vcgeneral
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

//#ifdef _MSC_VER
//# pragma warning(disable:4018) // C4018: signed/unsigned mismatch
//#endif // _MSC_VER

namespace { // unnamed

// Replacement of wcscpy_s which is not available on Windows XP's msvcrt
// http://sakuradite.com/topic/247
errno_t wcscpy_safe(wchar_t *buffer, size_t bufferSize, const wchar_t *source)
{
  size_t len = min(bufferSize - 1, wcslen(source));
  buffer[len] = 0;
  if (len)
    memcpy(buffer, source, len * 2);
  return 0;
}
} // unnamed namespace

NTINSPECT_BEGIN_NAMESPACE

// https://social.msdn.microsoft.com/Forums/vstudio/en-US/4cb11cd3-8ce0-49d7-9dda-d62e9ae0180b/how-to-get-current-module-handle?forum=vcgeneral
HMODULE getCurrentModuleHandle() { return (HMODULE)&__ImageBase; }

/** Memory range */

BOOL getProcessName(LPWSTR buffer, int bufferSize)
{
  //assert(name);
  PLDR_DATA_TABLE_ENTRY it;
  __asm
  {
    mov eax,fs:[0x30]
    mov eax,[eax+0xc]
    mov eax,[eax+0xc]
    mov it,eax
  }
  // jichi 6/4/2014: _s functions are not supported on Windows XP's msvcrt.dll
  //return 0 == wcscpy_s(buffer, bufferSize, it->BaseDllName.Buffer);
  return 0 == wcscpy_safe(buffer, bufferSize, it->BaseDllName.Buffer);
}

// See: ITH FillRange
BOOL getModuleMemoryRange(LPCWSTR moduleName, DWORD *lowerBound, DWORD *upperBound)
{
  //assert(lower);
  //assert(upper);
  PLDR_DATA_TABLE_ENTRY it;
  LIST_ENTRY *begin;
  __asm
  {
    mov eax,fs:[0x30]
    mov eax,[eax+0xc]
    mov eax,[eax+0xc]
    mov it,eax
    mov begin,eax
  }

  while (it->SizeOfImage) {
    if (_wcsicmp(it->BaseDllName.Buffer, moduleName) == 0) {
      DWORD lower = (DWORD)it->DllBase;
      if (lowerBound)
        *lowerBound = lower;

      if (upperBound) {
        DWORD upper = lower;
        MEMORY_BASIC_INFORMATION mbi = {};
        DWORD size = 0;
        do {
          DWORD len;
          // Nt function is needed instead of VirtualQuery, which only works for the current process
          ::NtQueryVirtualMemory(NtCurrentProcess(), (LPVOID)upper, MemoryBasicInformation, &mbi, sizeof(mbi), &len);
          if (mbi.Protect & PAGE_NOACCESS) {
            it->SizeOfImage = size;
            break;
          }
          size += mbi.RegionSize;
          upper += mbi.RegionSize;
        } while (size < it->SizeOfImage);

        *upperBound = upper;
      }
      return TRUE;
    }
    it = (PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink;
    if (it->InLoadOrderModuleList.Flink == begin)
      break;
  }
  return FALSE;
}

BOOL getProcessMemoryRange(DWORD *lowerBound, DWORD *upperBound)
{
  WCHAR procName[MAX_PATH]; // cached
  *lowerBound = 0;
  *upperBound = 0;
  return getProcessName(procName, MAX_PATH)
      && getModuleMemoryRange(procName, lowerBound, upperBound);
}

/** Module header */

// See: ITH AddAllModules
bool iterModule(const iter_module_fun_t &fun)
{
  // Iterate loaded modules
  PPEB ppeb;
  __asm {
    mov eax, fs:[0x30]
    mov ppeb, eax
  }
  const DWORD start = *(DWORD *)&ppeb->Ldr->InLoadOrderModuleList;
  for (auto it = (PLDR_DATA_TABLE_ENTRY)start;
      it->SizeOfImage && *(DWORD *)it != start;
      it = (PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink)
    if (!fun((HMODULE)it->DllBase, it->BaseDllName.Buffer))
      return false;
  return true;
}


// See: ITH AddAllModules
DWORD getExportFunction(LPCSTR funcName)
{
  // Iterate loaded modules
  PPEB ppeb;
  __asm {
    mov eax, fs:[0x30]
    mov ppeb, eax
  }
  const DWORD start = *(DWORD *)&ppeb->Ldr->InLoadOrderModuleList;
  for (auto it = (PLDR_DATA_TABLE_ENTRY)start;
      it->SizeOfImage && *(DWORD *)it != start;
      it = (PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink) {
    //if (moduleName && ::wcscmp(moduleName, it->BaseDllName.Buffer)) // BaseDllName.Buffer == moduleName
    //  continue;
    if (DWORD addr = getModuleExportFunction((HMODULE)it->DllBase, funcName))
      return addr;
  }
  return 0;
}

// See: ITH AddModule
DWORD getModuleExportFunction(HMODULE hModule, LPCSTR funcName)
{
  if (!hModule)
    return 0;
  DWORD startAddress = (DWORD)hModule;
  IMAGE_DOS_HEADER *DosHdr = (IMAGE_DOS_HEADER *)hModule;
  if (IMAGE_DOS_SIGNATURE == DosHdr->e_magic) {
    DWORD dwReadAddr = startAddress + DosHdr->e_lfanew;
    IMAGE_NT_HEADERS *NtHdr = (IMAGE_NT_HEADERS *)dwReadAddr;
    if (IMAGE_NT_SIGNATURE == NtHdr->Signature) {
      DWORD dwExportAddr = NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      if (dwExportAddr == 0)
        return 0;
      dwExportAddr += startAddress;
      IMAGE_EXPORT_DIRECTORY *ExtDir = (IMAGE_EXPORT_DIRECTORY *)dwExportAddr;
      dwExportAddr = startAddress + ExtDir->AddressOfNames;
      for (UINT uj = 0; uj < ExtDir->NumberOfNames; uj++) {
        DWORD dwFuncName = *(DWORD *)dwExportAddr;
        LPCSTR pcFuncName = (LPCSTR)(startAddress + dwFuncName);
        if (::strcmp(funcName, pcFuncName) == 0) {
          char *pcFuncPtr = (char *)(startAddress + (DWORD)ExtDir->AddressOfNameOrdinals+(uj * sizeof(WORD)));
          WORD word = *(WORD *)pcFuncPtr;
          pcFuncPtr = (char *)(startAddress + (DWORD)ExtDir->AddressOfFunctions+(word * sizeof(DWORD)));
          return startAddress + *(DWORD *)pcFuncPtr; // absolute address
        }
        dwExportAddr += sizeof(DWORD);
      }
    }
  }
  return 0;
}

// See: ITH FindImportEntry
DWORD getModuleImportAddress(HMODULE hModule, DWORD exportAddress)
{
  if (!hModule)
    return 0;
  DWORD startAddress = (DWORD)hModule;
  IMAGE_DOS_HEADER *DosHdr = (IMAGE_DOS_HEADER *)hModule;
  if (IMAGE_DOS_SIGNATURE == DosHdr->e_magic) {
    IMAGE_NT_HEADERS *NtHdr = (IMAGE_NT_HEADERS *)(startAddress + DosHdr->e_lfanew);
    if (IMAGE_NT_SIGNATURE == NtHdr->Signature) {
      DWORD IAT = NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
      DWORD end = NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
      IAT += startAddress;
      end += IAT;
      for (DWORD pt = IAT; pt < end; pt += 4) {
        DWORD addr = *(DWORD *)pt;
        if (addr == (DWORD)exportAddress)
          return pt;
      }
    }
  }
  return 0;
}

NTINSPECT_END_NAMESPACE

// EOF

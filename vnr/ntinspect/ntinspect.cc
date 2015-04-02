// ntinspect.cc
// 4/20/2014 jichi
#include "ntdll/ntdll.h"
#include "ntinspect/ntinspect.h"

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

BOOL getCurrentProcessName(LPWSTR buffer, int bufferSize)
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

BOOL getCurrentMemoryRange(DWORD *lowerBound, DWORD *upperBound)
{
  WCHAR procName[MAX_PATH]; // cached
  *lowerBound = 0;
  *upperBound = 0;
  return getCurrentProcessName(procName, MAX_PATH)
      && getModuleMemoryRange(procName, lowerBound, upperBound);
}

NTINSPECT_END_NAMESPACE

// EOF

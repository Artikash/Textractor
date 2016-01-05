#pragma once

// ith/common/memory.h
// 8/23/2013 jichi
// Branch: ITH/mem.h, revision 66

#ifndef ITH_HAS_HEAP
# define ITH_MEMSET_HEAP(...) ::memset(__VA_ARGS__)
#else
# define ITH_MEMSET_HEAP(...) (void)0

// Defined in kernel32.lilb
extern "C" {
// PVOID RtlAllocateHeap( _In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _In_ SIZE_T Size);
__declspec(dllimport) void * __stdcall RtlAllocateHeap(void *HeapHandle, unsigned long Flags, unsigned long Size);

// BOOLEAN RtlFreeHeap( _In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _In_ PVOID HeapBase);
__declspec(dllimport) int __stdcall RtlFreeHeap(void *HeapHandle, unsigned long Flags, void *HeapBase);
} // extern "C"

//NTSYSAPI
//BOOL
//NTAPI
//RtlFreeHeap(
//  _In_  HANDLE   hHeap,
//  _In_  DWORD    dwFlags,
//  _In_  LPVOID   lpMem
//);

extern void *hHeap; // defined in ith/sys.cc

inline void * __cdecl operator new(size_t lSize)
{
  // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366597%28v=vs.85%29.aspx
  // HEAP_ZERO_MEMORY flag is critical. All new objects are assumed with zero initialized.
  enum { HEAP_ZERO_MEMORY = 0x00000008 };
  return RtlAllocateHeap(::hHeap, HEAP_ZERO_MEMORY, lSize);
}

inline void __cdecl operator delete(void *pBlock)
{ RtlFreeHeap(::hHeap, 0, pBlock); }

inline void __cdecl operator delete[](void *pBlock)
{ RtlFreeHeap(::hHeap, 0, pBlock); }

#endif // ITH_HAS_HEAP

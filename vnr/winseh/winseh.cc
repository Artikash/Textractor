// winseh.cc
// 12/13/2013 jichi

#include "winseh/winseh.h"
#include "ntdll/ntdll.h"
//#include <cstdio>

// - Global variables -

seh_dword_t seh_esp[seh_capacity],
            seh_eip[seh_capacity],
            seh_eh[seh_capacity];
seh_dword_t seh_count;

// - Exception handlers -

// VC 2013: http://msdn.microsoft.com/en-us/library/b6sf5kbd.aspx
// typedef EXCEPTION_DISPOSITION (*PEXCEPTION_ROUTINE) (
//   _In_ PEXCEPTION_RECORD ExceptionRecord,
//   _In_ ULONG64 EstablisherFrame,
//   _Inout_ PCONTEXT ContextRecord,
//   _Inout_ PDISPATCHER_CONTEXT DispatcherContext
// );
//
// winnt.h: http://www.codemachine.com/downloads/win81/ntdef.h
// typedef
// __drv_sameIRQL
// __drv_functionClass(EXCEPTION_ROUTINE)
// EXCEPTION_DISPOSITION
// NTAPI
// EXCEPTION_ROUTINE (
//     _Inout_ struct _EXCEPTION_RECORD *ExceptionRecord,
//     _In_ PVOID EstablisherFrame,
//     _In_ struct _CONTEXT *ContextRecord,
//     _In_ PVOID DispatcherContext
//     );
extern "C" EXCEPTION_DISPOSITION _seh_handler( // extern C is needed to avoid name hashing in C++
  _In_ PEXCEPTION_RECORD ExceptionRecord,
  _In_ PVOID EstablisherFrame,     // does not work if I use ULONG64
  _Inout_ PCONTEXT ContextRecord,
  _In_ PVOID DispatcherContext) // PDISPATCHER_CONTEXT is not declared in windows.h
{
  //assert(::seh_count > 0);
  ContextRecord->Esp = ::seh_esp[::seh_count - 1];
  ContextRecord->Eip = ::seh_eip[::seh_count - 1];
  //printf("seh_handler:%i,%x,%x\n", ::seh_count, ContextRecord->Esp, ContextRecord->Eip);
  return ::seh_eh[::seh_count - 1] ?
      reinterpret_cast<PEXCEPTION_ROUTINE>(::seh_eh[::seh_count - 1])(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext) :
      ExceptionContinueExecution;
}

// EOF

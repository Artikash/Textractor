// winseh_unsafe.cc
// 12/13/2013 jichi
// See: http://stackoverflow.com/questions/19722308/exception-handler-not-called-in-c

#include "winseh/winseh.h"
#include <windows.h>

extern "C" EXCEPTION_DISPOSITION _seh_handler(PEXCEPTION_RECORD, PVOID, PCONTEXT, PVOID);
seh_dword_t seh_handler = reinterpret_cast<seh_dword_t>(_seh_handler);

// EOF

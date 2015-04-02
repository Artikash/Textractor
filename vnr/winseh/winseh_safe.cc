// winseh_safe.cc
// 12/13/2013 jichi
// See: http://stackoverflow.com/questions/12019689/custom-seh-handler-with-safeseh

#include "winseh/winseh.h"

extern "C" int __stdcall _seh_asm_handler();
seh_dword_t seh_handler = reinterpret_cast<seh_dword_t>(_seh_asm_handler);

// EOF

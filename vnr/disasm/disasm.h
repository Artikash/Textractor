#pragma once
// disasm.h
// 1/27/2013 jichi

// Include typedef of BYTE
//#include <windef.h>
#include <windows.h>

//#ifdef QT_CORE_LIB
//# include <qt_windows.h>
//#else
//# include <windows.h>
//#endif

#ifndef DISASM_BEGIN_NAMESPACE
# define DISASM_BEGIN_NAMESPACE
#endif
#ifndef DISASM_END_NAMESPACE
# define DISASM_END_NAMESPACE
#endif

DISASM_BEGIN_NAMESPACE
int disasm(const BYTE *opcode0); // return: op length if success, 0 if error
DISASM_END_NAMESPACE

// EOF

#pragma once

// ntinspect.h
// 4/20/2014 jichi

#include <windows.h>

#ifndef NTINSPECT_BEGIN_NAMESPACE
# define NTINSPECT_BEGIN_NAMESPACE  namespace NtInspect {
#endif
#ifndef NTINSPECT_END_NAMESPACE
# define NTINSPECT_END_NAMESPACE    } // NtInspect
#endif

NTINSPECT_BEGIN_NAMESPACE

///  Get current module name in fs:0x30
BOOL getCurrentProcessName(_Out_ LPWSTR buffer, _In_ int bufferSize);

/**
 *  Get the memory range of the module if succeed
 *  See: ITH FillRange
 */
BOOL getModuleMemoryRange(_In_ LPCWSTR moduleName, _Out_ DWORD *lowerBound, _Out_ DWORD *upperBound);

///  Get memory of the current process
BOOL getCurrentMemoryRange(_Out_ DWORD *lowerBound, _Out_ DWORD *upperBound);

NTINSPECT_END_NAMESPACE

// EOF

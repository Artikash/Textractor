#pragma once

// unload.h
// 5/2/2014 jichi

#include "windbg/windbg.h"
#include <windows.h>

WINDBG_BEGIN_NAMESPACE

/**
 *  Unload current injected DLL.
 *  @return  BOOL
 */
BOOL unloadCurrentModule();

WINDBG_END_NAMESPACE

// EOF

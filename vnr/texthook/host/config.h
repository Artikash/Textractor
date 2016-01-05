#pragma once

// config.h
// 8/23/2013 jichi
// The first header file that are included by all source files.

#define IHF // for dll import
//#include "ith/dllconfig.h"
#define IHFAPI __stdcall
#ifdef IHF
# define IHFSERVICE __declspec(dllexport)
#else
# define IHFSERVICE __declspec(dllimport)
#endif

// EOF

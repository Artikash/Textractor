#pragma once

// ith/common/except.h
// 9/17/2013 jichi

#define ITH_RAISE  (*(int*)0 = 0) // raise C000005, for debugging only

#ifdef ITH_HAS_SEH

# define ITH_TRY    __try
# define ITH_EXCEPT __except(EXCEPTION_EXECUTE_HANDLER)
# define ITH_WITH_SEH(...) \
  ITH_TRY { __VA_ARGS__; } ITH_EXCEPT {}

#else  // for old msvcrt.dll on Windows XP that does not have exception handler

// Currently, only with_seh is implemented. Try and catch are not.
# define ITH_TRY    if (true)
# define ITH_EXCEPT else
# include "winseh/winseh.h"
# define ITH_WITH_SEH(...) seh_with(__VA_ARGS__)

#endif // ITH_HAS_SEH

// EOF

#pragma once
// winmutex.h
// 12/11/2011 jichi

#include <windows.h>

#ifdef _MSC_VER
# pragma warning(disable:4800) // C4800: forcing value to bool
#endif // _MSC_VER

  class MutexLocker
  {
	  HANDLE m;
  public:
	  explicit MutexLocker(HANDLE mutex) : m(mutex)
	  {
		  WaitForSingleObject(m, 0);
	  }
	  ~MutexLocker() { if (m != INVALID_HANDLE_VALUE && m != nullptr) ReleaseMutex(m); }
  };

  class CriticalSectionLocker
  {
	  CRITICAL_SECTION cs;
  public:
	  explicit CriticalSectionLocker(CRITICAL_SECTION cs) : cs(cs)
	  {
		  EnterCriticalSection(&cs);
	  }
	  ~CriticalSectionLocker() { LeaveCriticalSection(&cs); }
  };

// EOF

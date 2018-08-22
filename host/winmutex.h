#pragma once
// winmutex.h
// 12/11/2011 jichi

#include <windows.h>

#ifdef _MSC_VER
# pragma warning(disable:4800) // C4800: forcing value to bool
#endif // _MSC_VER

// Artikash 7/20/2018: similar to std::lock guard but use Winapi objects for cross process comms

class MutexLocker
{
	HANDLE mutex;
public:
	explicit MutexLocker(HANDLE mutex) : mutex(mutex) { WaitForSingleObject(mutex, 0); }
	~MutexLocker() { if (mutex != INVALID_HANDLE_VALUE && mutex != nullptr) ReleaseMutex(mutex); }
};

// EOF

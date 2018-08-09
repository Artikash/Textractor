#pragma once
// winmutex.h
// 12/11/2011 jichi

#include <windows.h>

#ifdef _MSC_VER
# pragma warning(disable:4800) // C4800: forcing value to bool
#endif // _MSC_VER

// Artikash 7/20/2018: these are similar to std::lock guard but use Winapi objects

class MutexLocker
{
	HANDLE mutex;
public:
	explicit MutexLocker(HANDLE mutex) : mutex(mutex)
	{
		WaitForSingleObject(mutex, 0);
	}
	~MutexLocker() { if (mutex != INVALID_HANDLE_VALUE && mutex != nullptr) ReleaseMutex(mutex); }
};

class CriticalSectionLocker
{
	CRITICAL_SECTION* cs;
public:
	explicit CriticalSectionLocker(CRITICAL_SECTION* cs) : cs(cs)
	{
		EnterCriticalSection(cs);
	}
	~CriticalSectionLocker() { LeaveCriticalSection(cs); }
};

// EOF

#pragma once
// winmutex.h
// 12/11/2011 jichi

#include <windows.h>
#include "common.h"

// Artikash 7/20/2018: similar to std::lock guard but use Winapi objects for cross process comms

class MutexLocker
{
	HANDLE mutex;
public:
	MutexLocker(HANDLE mutex) : mutex(mutex) { WaitForSingleObject(mutex, 0); }
	~MutexLocker() { if (mutex != INVALID_HANDLE_VALUE && mutex != nullptr) ReleaseMutex(mutex); }
};

// EOF

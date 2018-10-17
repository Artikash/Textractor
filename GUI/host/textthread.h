#pragma once

// textthread.h
// 8/23/2013 jichi
// Branch: ITH/TextThread.h, rev 120

#include "common.h"
#include "types.h"
#include <unordered_set>

class TextThread
{
public:
	typedef std::function<bool(TextThread*, std::wstring&)> OutputCallback;

	inline static OutputCallback Output;

	inline static int flushDelay = 250; // flush every 250ms by default
	inline static int maxBufferSize = 200;
	inline static int threadCounter = 0;

	TextThread(ThreadParam tp, DWORD status);
	~TextThread();

	std::wstring GetStorage();
	void AddText(const BYTE* data, int len);
	void AddSentence(std::wstring sentence);

	const int64_t handle;
	const std::wstring name;
	const ThreadParam tp;

private:
	void Flush();

	std::wstring buffer;
	std::wstring storage;
	std::unordered_set<wchar_t> repeatingChars;
	std::recursive_mutex ttMutex;
	DWORD status;

	HANDLE deletionEvent = CreateEventW(nullptr, FALSE, FALSE, NULL);
	std::thread flushThread = std::thread([&] { while (WaitForSingleObject(deletionEvent, 10) == WAIT_TIMEOUT) Flush(); });
	DWORD timestamp = GetTickCount();
};

// EOF

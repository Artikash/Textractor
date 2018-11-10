#pragma once

// textthread.h
// 8/23/2013 jichi
// Branch: ITH/TextThread.h, rev 120

#include "common.h"
#include "types.h"

class TextThread
{
public:
	typedef std::function<bool(TextThread*, std::wstring&)> OutputCallback;

	inline static OutputCallback Output;

	inline static int flushDelay = 400; // flush every 400ms by default
	inline static int maxBufferSize = 1000;
	inline static int defaultCodepage = SHIFT_JIS;
	inline static int threadCounter = 0;

	TextThread(ThreadParam tp, HookParam hp, std::wstring name);
	~TextThread();

	std::wstring GetStorage();
	void AddSentence(std::wstring sentence);
	void Push(const BYTE* data, int len);

	const int64_t handle;
	const std::wstring name;
	const ThreadParam tp;
	const HookParam hp;

private:
	void Flush();

	std::wstring buffer;
	std::wstring storage;
	std::unordered_set<wchar_t> repeatingChars;
	std::recursive_mutex threadMutex;

	HANDLE deletionEvent = CreateEventW(nullptr, FALSE, FALSE, NULL);
	std::thread flushThread = std::thread([&] { while (WaitForSingleObject(deletionEvent, 10) == WAIT_TIMEOUT) Flush(); });
	DWORD lastPushTime = GetTickCount();
};

// EOF

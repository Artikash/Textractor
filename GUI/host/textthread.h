#pragma once

#include "common.h"
#include "types.h"

class TextThread
{
public:
	using OutputCallback = std::function<bool(TextThread&, std::wstring&)>;
	inline static OutputCallback Output;

	inline static bool filterRepetition = true;
	inline static int flushDelay = 400; // flush every 400ms by default
	inline static int maxBufferSize = 1000;

	TextThread(ThreadParam tp, HookParam hp, std::optional<std::wstring> name = {});

	void Start();
	void Stop();
	void AddSentence(std::wstring&& sentence);
	void Push(BYTE* data, int length);

	ThreadSafe<std::wstring> storage;
	const int64_t handle;
	const std::wstring name;
	const ThreadParam tp;
	const HookParam hp;

private:
	inline static int threadCounter = 0;

	void Flush();

	std::wstring buffer;
	BYTE leadByte = 0;
	std::unordered_set<wchar_t> repeatingChars;
	std::mutex bufferMutex;
	DWORD lastPushTime = 0;
	ThreadSafe<std::deque<std::wstring>> queuedSentences;
	struct TimerDeleter { void operator()(HANDLE h) { DeleteTimerQueueTimer(NULL, h, INVALID_HANDLE_VALUE); } };
	AutoHandle<TimerDeleter> timer = NULL;
};

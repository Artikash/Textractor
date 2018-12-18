#pragma once

#include "common.h"
#include "types.h"

class TextThread
{
public:
	using EventCallback = std::function<void(TextThread*)>;
	using OutputCallback = std::function<bool(TextThread*, std::wstring&)>;
	inline static EventCallback OnCreate, OnDestroy;
	inline static OutputCallback Output;

	inline static int flushDelay = 400; // flush every 400ms by default
	inline static int maxBufferSize = 1000;
	inline static int defaultCodepage = SHIFT_JIS;
	inline static int threadCounter = 0;

	TextThread(ThreadParam tp, HookParam hp, std::optional<std::wstring> name = {});
	~TextThread();

	void AddSentence(std::wstring sentence);
	void Push(const BYTE* data, int len);

	const ThreadSafePtr<std::wstring> storage;
	const int64_t handle;
	const std::wstring name;
	const ThreadParam tp;
	const HookParam hp;

private:
	void Flush();

	struct TimerDeleter { void operator()(void* h) { DeleteTimerQueueTimer(NULL, h, INVALID_HANDLE_VALUE); } };
	std::wstring buffer;
	std::unordered_set<wchar_t> repeatingChars;
	std::mutex bufferMutex;
	DWORD lastPushTime;
	AutoHandle<TimerDeleter> timer = NULL; // this needs to be last so it's destructed first
};

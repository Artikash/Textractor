#pragma once

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
	TextThread(TextThread&) = delete;
	TextThread& operator=(TextThread) = delete;
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
	std::unordered_set<wchar_t> repeatingChars;
	std::mutex bufferMutex;
	std::wstring storage;
	std::mutex storageMutex;
	HANDLE deletionEvent;
	std::thread flushThread;
	DWORD lastPushTime;
};

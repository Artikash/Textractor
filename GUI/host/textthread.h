#pragma once

// textthread.h
// 8/23/2013 jichi
// Branch: ITH/TextThread.h, rev 120

#include "common.h"
#include "types.h"

class TextThread
{
	typedef std::function<std::wstring(TextThread*, std::wstring)> ThreadOutputCallback;

public:
	TextThread(ThreadParam tp, DWORD status);
	~TextThread();

	std::wstring GetStore();
	void AddText(const BYTE* data, int len);
	void AddSentence(std::wstring sentence);
	void RegisterOutputCallBack(ThreadOutputCallback cb) { Output = cb; }

	const int64_t handle;
	const std::wstring name;
	const ThreadParam tp;

	inline static int FlushDelay = 250; // flush every 250ms by default
	inline static int MaxBufferSize = 500; 
	inline static int ThreadCounter = 0;

private:
	void Flush();

	std::wstring buffer;
	std::wstring storage;
	std::recursive_mutex ttMutex;
	std::thread flusher = std::thread([] {});
	HANDLE cancelFlushEvent = CreateEventW(nullptr, TRUE, TRUE, NULL);

	ThreadOutputCallback Output;
	DWORD status;
};

// EOF

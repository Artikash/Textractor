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
	ThreadParam GetThreadParam() { return tp; }

	void RegisterOutputCallBack(ThreadOutputCallback cb) { Output = cb; }

	void AddText(const BYTE *con, int len);
	void AddSentence(std::wstring sentence);	

private:
	void Flush();

	std::vector<char> buffer;
	std::wstring storage;

	std::recursive_mutex ttMutex;
	HANDLE deletionEvent;
	std::thread flushThread;
	DWORD timestamp;

	ThreadOutputCallback Output;
	ThreadParam tp;
	DWORD status;
};

// EOF

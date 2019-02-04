#pragma once

#include "common.h"
#include "textthread.h"

namespace Host
{
	using ProcessEventHandler = std::function<void(DWORD)>;
	using ThreadEventHandler = std::function<void(TextThread&)>;
	void Start(ProcessEventHandler Connect, ProcessEventHandler Disconnect, ThreadEventHandler Create, ThreadEventHandler Destroy, TextThread::OutputCallback Output);

	bool InjectProcess(DWORD processId, DWORD timeout = 5000);
	void DetachProcess(DWORD processId);
	void InsertHook(DWORD processId, HookParam hp);

	HookParam GetHookParam(ThreadParam tp);

	TextThread& GetThread(ThreadParam tp);
	void AddConsoleOutput(std::wstring text);

	inline int defaultCodepage = SHIFT_JIS;

	constexpr ThreadParam console{ 0, -1LL, -1LL, -1LL }, clipboard{ 0, 0, -1LL, -1LL };
}

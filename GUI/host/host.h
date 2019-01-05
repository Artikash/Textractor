#pragma once

#include "common.h"
#include "textthread.h"

namespace Host
{
	using ProcessEventCallback = std::function<void(DWORD)>;
	void Start(ProcessEventCallback OnConnect, ProcessEventCallback OnDisconnect, TextThread::EventCallback OnCreate, TextThread::EventCallback OnDestroy, TextThread::OutputCallback Output);

	bool InjectProcess(DWORD processId, DWORD timeout = 5000);
	void DetachProcess(DWORD processId);
	void InsertHook(DWORD processId, HookParam hp);

	HookParam GetHookParam(ThreadParam tp);

	std::shared_ptr<TextThread> GetThread(ThreadParam tp);
	void AddConsoleOutput(std::wstring text);

	inline int defaultCodepage = SHIFT_JIS;
}

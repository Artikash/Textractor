#pragma once

#include "common.h"
#include "textthread.h"

namespace Host
{
	typedef std::function<void(DWORD)> ProcessEventCallback;
	void Start(ProcessEventCallback OnConnect, ProcessEventCallback OnDisconnect, TextThread::EventCallback OnCreate, TextThread::EventCallback OnDestroy, TextThread::OutputCallback Output);

	bool InjectProcess(DWORD processId, DWORD timeout = 5000);
	void DetachProcess(DWORD processId);
	void InsertHook(DWORD processId, HookParam hp, std::string name = "");

	HookParam GetHookParam(DWORD processId, uint64_t addr);
	inline HookParam GetHookParam(ThreadParam tp) { return GetHookParam(tp.processId, tp.addr); }
	std::wstring GetHookName(DWORD processId, uint64_t addr);
	inline std::wstring GetHookName(ThreadParam tp) { return GetHookName(tp.processId, tp.addr); }

	std::shared_ptr<TextThread> GetThread(ThreadParam tp);
	void AddConsoleOutput(std::wstring text);
}

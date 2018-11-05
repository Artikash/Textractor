#pragma once

// host.h
// 8/23/2013 jichi
// Branch: ITH/IHF.h, rev 105

#include "common.h"
#include "textthread.h"

typedef std::function<void(DWORD)> ProcessEventCallback;
typedef std::function<void(std::shared_ptr<TextThread>)> ThreadEventCallback;

namespace Host
{
	void Start(ProcessEventCallback onAttach, ProcessEventCallback onDetach, ThreadEventCallback onCreate, ThreadEventCallback onDestroy, TextThread::OutputCallback output);
	void Close();

	bool InjectProcess(DWORD processId, DWORD timeout = 5000);
	void DetachProcess(DWORD processId);

	void InsertHook(DWORD processId, HookParam hp, std::string name = "");
	void RemoveHook(DWORD processId, uint64_t addr);

	HookParam GetHookParam(DWORD processId, uint64_t addr);
	inline HookParam GetHookParam(ThreadParam tp) { return GetHookParam(tp.processId, tp.addr); }
	std::wstring GetHookName(DWORD processId, uint64_t addr);
	inline std::wstring GetHookName(ThreadParam tp) { return GetHookName(tp.processId, tp.addr); }

	std::shared_ptr<TextThread> GetThread(ThreadParam tp);
	void AddConsoleOutput(std::wstring text);
}

inline UINT CURRENT_CODEPAGE = SHIFT_JIS;
inline std::wstring StringToWideString(const std::string& text, UINT encoding = CURRENT_CODEPAGE)
{
	std::wstring ret(text.size() + 1, 0);
	ret.resize(MultiByteToWideChar(encoding, 0, text.c_str(), -1, ret.data(), ret.capacity()) - 1);
	return ret;
}

// EOF

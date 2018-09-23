#pragma once

// host.h
// 8/23/2013 jichi
// Branch: ITH/IHF.h, rev 105

#include "common.h"
#include "textthread.h"

typedef std::function<void(DWORD)> ProcessEventCallback;
typedef std::function<void(TextThread*)> ThreadEventCallback;

namespace Host
{
	void Start(ProcessEventCallback onAttach, ProcessEventCallback onDetach, ThreadEventCallback onCreate, ThreadEventCallback onRemove);
	void Close();

	bool InjectProcess(DWORD pid, DWORD timeout = 5000);
	void DetachProcess(DWORD pid);

	void InsertHook(DWORD pid, HookParam hp, std::string name = "");
	void RemoveHook(DWORD pid, uint64_t addr);

	HookParam GetHookParam(DWORD pid, uint64_t addr);
	HookParam GetHookParam(ThreadParam tp);
	std::wstring GetHookName(DWORD pid, uint64_t addr);

	TextThread* GetThread(ThreadParam tp);
	void AddConsoleOutput(std::wstring text);
}

inline std::wstring StringToWideString(const std::string& text, UINT encoding)
{
	std::wstring ret(text.size(), 0);
	ret.resize(MultiByteToWideChar(encoding, 0, text.c_str(), -1, ret.data(), ret.capacity()));
	return ret;
}

// EOF

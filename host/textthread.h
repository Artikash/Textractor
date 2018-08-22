#pragma once

// textthread.h
// 8/23/2013 jichi
// Branch: ITH/TextThread.h, rev 120

#include <Windows.h>
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <thread>

struct ThreadParameter
{
	DWORD pid; // jichi: 5/11/2014: The process ID
	unsigned __int64 hook; // Artikash 6/6/2018: The insertion address of the hook
	unsigned __int64 retn; // jichi 5/11/2014: The return address of the hook
	unsigned __int64 spl;  // jichi 5/11/2014: the processed split value of the hook paramete

	// Artikash 5/31/2018: required for unordered_map to work with struct key
	friend bool operator==(const ThreadParameter& one, const ThreadParameter& two)
	{
		return one.pid == two.pid && one.hook == two.hook && one.retn == two.retn && one.spl == two.spl;
	}
};

class TextThread;
typedef std::function<std::wstring(TextThread*, std::wstring)> ThreadOutputCallback;

//extern DWORD split_time,repeat_count,global_filter,cyclic_remove;

class TextThread
{
public:
	TextThread(ThreadParameter tp, DWORD status);
	virtual ~TextThread();

	virtual std::wstring GetStore();
	ThreadParameter GetThreadParameter() { return tp; }

	void RegisterOutputCallBack(ThreadOutputCallback cb) { Output = cb; }

	void AddText(const BYTE *con, int len);
	void AddSentence(std::wstring sentence);	

private:
	bool Flush();

	std::vector<char> buffer;
	std::wstring storage;
	std::recursive_mutex ttMutex;
	HANDLE deletionEvent;
	std::thread flushThread;
	
	DWORD timestamp;
	ThreadOutputCallback Output;
	ThreadParameter tp;
	DWORD status;
};

// EOF

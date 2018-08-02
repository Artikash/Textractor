#pragma once

// textthread.h
// 8/23/2013 jichi
// Branch: ITH/TextThread.h, rev 120

#include <Windows.h>
#include <string>
#include <vector>
#include <functional>

struct ThreadParameter
{
	DWORD pid; // jichi: 5/11/2014: The process ID
	DWORD hook; // Artikash 6/6/2018: The start address of the hook
	DWORD retn; // jichi 5/11/2014: The return address of the hook
	DWORD spl;  // jichi 5/11/2014: the processed split value of the hook paramete

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
	TextThread(ThreadParameter tp, unsigned int threadNumber, DWORD status);
	~TextThread();

	virtual std::wstring GetStore();
	WORD Number() const { return threadNumber; }
	ThreadParameter GetThreadParameter() { return tp; }

	void RegisterOutputCallBack(ThreadOutputCallback cb) { output = cb; }

	void Clear();
	void AddText(const BYTE *con, int len);
	void AddSentence();
	void AddSentence(std::wstring sentence);	

private:
	CRITICAL_SECTION ttCs;
	ThreadOutputCallback output;
	std::vector<char> sentenceBuffer;
	std::wstring storage;

	ThreadParameter tp;
	unsigned int threadNumber;
	DWORD status;
	unsigned int flushTimer;
};

// EOF

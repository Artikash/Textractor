#pragma once

// textthread.h
// 8/23/2013 jichi
// Branch: ITH/TextThread.h, rev 120

#include <Windows.h>
#include <string>
#include <vector>

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

#define CURRENT_SELECT 0x1000

class TextThread;
typedef std::wstring(*ThreadOutputCallback)(TextThread*, std::wstring data);

//extern DWORD split_time,repeat_count,global_filter,cyclic_remove;

class TextThread
{
public:
	TextThread(ThreadParameter tp, unsigned int threadNumber, unsigned int splitDelay);
	~TextThread();

	void Reset();
	void AddText(const BYTE *con, int len);
	void AddSentence();
	void AddSentence(std::wstring sentence);

	std::wstring GetStore() { return storage; }
	DWORD &Status() { return status; }
	WORD Number() const { return threadNumber; }
	ThreadParameter GetThreadParameter() { return tp; }

	void RegisterOutputCallBack(ThreadOutputCallback cb) { output = cb; }

private:
	CRITICAL_SECTION ttCs;
	ThreadOutputCallback output;
	std::vector<char> sentenceBuffer;
	std::wstring storage;

	ThreadParameter tp;
	unsigned int threadNumber;
	unsigned int splitDelay;
	DWORD status;
};

// EOF

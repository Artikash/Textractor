#pragma once
#include "ITH.h"
#include "utility.h" // UniqueHandle, CriticalSection

class TextBuffer
{
public:
	TextBuffer(HWND edit);
	~TextBuffer();
	void Flush();
	void AddText(LPCWSTR str, int len, bool line);
	void ClearBuffer();
	bool Running() { return running; }
private:
	CriticalSection cs;
	bool line_break, running;
	UniqueHandle hThread;
	HWND hEdit;
	std::wstring str;
};

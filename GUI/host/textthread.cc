// textthread.cc
// 8/24/2013 jichi
// Branch IHF/TextThread.cpp, rev 133

#include "textthread.h"
#include "const.h"

TextThread::TextThread(ThreadParam tp, DWORD status) : tp(tp), status(status) {}

TextThread::~TextThread()
{
	SetEvent(deletionEvent);
	flushThread.join();
	CloseHandle(deletionEvent);
}

std::wstring TextThread::GetStore()
{
	LOCK ttLock(ttMutex);
	return storage;
}

void TextThread::Flush()
{
	LOCK ttLock(ttMutex);
	if (buffer.size() < 400 && (timestamp - GetTickCount() < 250 || buffer.size() == 0)) return; // TODO: let user change delay before sentence is flushed
	std::wstring sentence;
	if (status & USING_UNICODE)
	{
		sentence = std::wstring((wchar_t*)buffer.data(), buffer.size() / 2);
	}
	else
	{
		wchar_t* converted = new wchar_t[buffer.size()];
		sentence = std::wstring(converted, MultiByteToWideChar(status & USING_UTF8 ? CP_UTF8 : 932, 0, buffer.data(), buffer.size(), converted, buffer.size()));
		delete[] converted;
	}
	ttMutex.unlock();
	AddSentence(sentence);
	ttMutex.lock();
	memset(buffer.data(), 0, buffer.size());
	buffer.clear();
}

void TextThread::AddSentence(std::wstring sentence)
{
	if (Output) sentence = Output(this, sentence);
	LOCK ttLock(ttMutex);
	storage.append(sentence);
}

void TextThread::AddText(const BYTE *con, int len)
{
	LOCK ttLock(ttMutex);
	// Artikash 8/27/2018: add repetition filter
	if (len > 6 && buffer.data() && (strstr(buffer.data(), (const char*)con) || wcsstr((const wchar_t*)buffer.data(), (const wchar_t*)con))) return;
	buffer.insert(buffer.end(), con, con + len);
	timestamp = GetTickCount();
}

// EOF

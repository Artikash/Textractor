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
	LOCK(ttMutex);
}

std::wstring TextThread::GetStore()
{
	LOCK(ttMutex);
	return storage;
}

void TextThread::Flush()
{
	std::wstring sentence;
	{
		LOCK(ttMutex);
		if (buffer.size() < 400 && (GetTickCount() - timestamp < 250 || buffer.size() == 0)) return; // TODO: let user change delay before sentence is flushed
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
		buffer.clear();
	}
	AddSentence(sentence);
}

void TextThread::AddSentence(std::wstring sentence)
{
	// Dispatch to extensions occurs here. Don't hold mutex! Extensions might take a while!
	if (Output) sentence = Output(this, sentence);
	LOCK(ttMutex);
	storage.append(sentence);
}

void TextThread::AddText(const BYTE* data, int len)
{
	LOCK(ttMutex);
	buffer.insert(buffer.end(), data, data + len);
	timestamp = GetTickCount();
}

// EOF

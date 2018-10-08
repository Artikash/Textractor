// textthread.cc
// 8/24/2013 jichi
// Branch IHF/TextThread.cpp, rev 133

#include "textthread.h"
#include "host.h"
#include "const.h"

TextThread::TextThread(ThreadParam tp, DWORD status) : handle(ThreadCounter++), name(Host::GetHookName(tp.pid, tp.hook)), tp(tp), status(status) {}

TextThread::~TextThread()
{
	SetEvent(deletionEvent);
	flushThread.join();
	CloseHandle(deletionEvent);
}

std::wstring TextThread::GetStorage()
{
	LOCK(ttMutex);
	return storage;
}

void TextThread::Flush()
{
	std::wstring sentence;
	{
		LOCK(ttMutex);
		if (buffer.size() < MaxBufferSize && (GetTickCount() - timestamp < FlushDelay || buffer.size() < 2)) return;
		sentence = buffer;
		buffer.clear();
	}
	AddSentence(sentence);
}

void TextThread::AddSentence(std::wstring sentence)
{
	// Dispatch to extensions occurs here. Don't hold mutex! Extensions might take a while!
	if (Output(this, sentence))
	{
		LOCK(ttMutex);
		storage += sentence;
	}
}

void TextThread::AddText(const BYTE* data, int len)
{
	LOCK(ttMutex);
	buffer += status & USING_UNICODE
		? std::wstring((wchar_t*)data, len / 2)
		: StringToWideString(std::string((char*)data, len), status & USING_UTF8 ? CP_UTF8 : SHIFT_JIS);
	if (Filter) Filter(buffer.data(), storage.c_str());
	timestamp = GetTickCount();
}

// EOF

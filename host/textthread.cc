// textthread.cc
// 8/24/2013 jichi
// Branch IHF/TextThread.cpp, rev 133
#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "textthread.h"
#include <mutex>
#include "../vnrhook/include/const.h"
#include "winmutex.h"

#define TT_LOCK std::lock_guard<std::recursive_mutex> ttLocker(ttMutex) // Synchronized scope for accessing private data

TextThread::TextThread(ThreadParameter tp, DWORD status) :
	status(status),
	timestamp(GetTickCount()),
	Output(nullptr),
	tp(tp),
	flushThread([&]() { while (Sleep(25), FlushSentenceBuffer()); })
{}

TextThread::~TextThread()
{
	status = -1UL;
	flushThread.join();
}

std::wstring TextThread::GetStore()
{
	TT_LOCK;
	return storage;
}

bool TextThread::FlushSentenceBuffer()
{
	TT_LOCK;
	if (status == -1UL) return false;
	if (timestamp - GetTickCount() < 250 || sentenceBuffer.size() == 0) return true; // TODO: let user change delay before sentence is flushed
	std::wstring sentence;
	if (status & USING_UNICODE)
	{
		sentence = std::wstring((wchar_t*)sentenceBuffer.data(), sentenceBuffer.size() / 2);
	}
	else if (status & USING_UTF8)
	{
		wchar_t* converted = new wchar_t[sentenceBuffer.size()];
		sentence = std::wstring(converted, MultiByteToWideChar(CP_UTF8, 0, sentenceBuffer.data(), sentenceBuffer.size(), converted, sentenceBuffer.size()));
		delete[] converted;
	}
	else
	{
		wchar_t* converted = new wchar_t[sentenceBuffer.size()];
		sentence = std::wstring(converted, MultiByteToWideChar(932, 0, sentenceBuffer.data(), sentenceBuffer.size(), converted, sentenceBuffer.size()));
		delete[] converted;
	}
	AddSentence(sentence);
	sentenceBuffer.clear();
	return true;
}

void TextThread::AddSentence(std::wstring sentence)
{
	TT_LOCK;
	if (Output) sentence = Output(this, sentence);
	storage.append(sentence);
}

void TextThread::AddText(const BYTE *con, int len)
{
	TT_LOCK;
	sentenceBuffer.insert(sentenceBuffer.end(), con, con + len);
	timestamp = GetTickCount();
}

// EOF

// textthread.cc
// 8/24/2013 jichi
// Branch IHF/TextThread.cpp, rev 133
#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "textthread.h"
#include "../vnrhook/include/const.h"
#include "winmutex.h"

extern HWND dummyWindow;

#define TT_LOCK CriticalSectionLocker ttLocker(ttCs) // Synchronized scope for accessing private data

TextThread::TextThread(ThreadParameter tp, unsigned int threadNumber, DWORD status) :
	storage(),
	sentenceBuffer(),
	status(status),
	flushTimer(0),
	threadNumber(threadNumber),
	output(nullptr),
	tp(tp)
{
	InitializeCriticalSection(&ttCs);
}

TextThread::~TextThread()
{
	EnterCriticalSection(&ttCs);
	KillTimer(dummyWindow, flushTimer);
	LeaveCriticalSection(&ttCs);
	DeleteCriticalSection(&ttCs);
}

void TextThread::Clear()
{
	TT_LOCK;
	storage.clear();
	storage.shrink_to_fit();
}

std::wstring TextThread::GetStore()
{
	TT_LOCK;
	return storage;
}

void TextThread::AddSentence()
{
	TT_LOCK;
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
}

void TextThread::AddSentence(std::wstring sentence)
{
	TT_LOCK;
	sentence.append(L"\r\n");
	if (output) sentence = output(this, sentence);
	storage.append(sentence);
}

void TextThread::AddText(const BYTE *con, int len)
{
	TT_LOCK;
	sentenceBuffer.insert(sentenceBuffer.end(), con, con + len);
	flushTimer = SetTimer(dummyWindow, (UINT_PTR)this, 250, // TODO: Let user change delay before sentenceBuffer is flushed
		[](HWND hWnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
	{
		KillTimer(hWnd, idEvent);
		((TextThread*)idEvent)->AddSentence();
	});
}

// EOF

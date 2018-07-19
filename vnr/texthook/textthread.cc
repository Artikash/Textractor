// textthread.cc
// 8/24/2013 jichi
// Branch IHF/TextThread.cpp, rev 133
#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "host.h"
#include "textthread.h"
#include "vnrhook/include/const.h"
#include "extensions/Extensions.h"
#include "winmutex/winmutex.h"

extern HookManager* man;
extern HWND dummyWindow;

#define TT_LOCK CriticalSectionLocker locker(ttCs) // Synchronized scope for accessing private data

TextThread::TextThread(ThreadParameter tp, unsigned int threadNumber, unsigned int splitDelay) :
	storage(),
	sentenceBuffer(),
	status(0),
	threadNumber(threadNumber),
	splitDelay(splitDelay),
	output(nullptr),
	tp(tp)
{
	InitializeCriticalSection(&ttCs);
}

TextThread::~TextThread()
{
	TT_LOCK;
	DeleteCriticalSection(&ttCs);
}

void TextThread::Reset()
{
	TT_LOCK;
	storage.clear();
}

void TextThread::AddSentence()
{
	TT_LOCK;
	std::wstring sentence;
	if (status & USING_UNICODE)
	{
		sentence = std::wstring((wchar_t*)sentenceBuffer.data(), sentenceBuffer.size() / 2);
	}
	else
	{
		wchar_t* converted = new wchar_t[sentenceBuffer.size()];
		sentence = std::wstring(converted, MultiByteToWideChar(932, 0, sentenceBuffer.data(), sentenceBuffer.size(), converted, sentenceBuffer.size()));
		delete[] converted;
	}
	AddSentence(DispatchSentenceToExtensions(sentence, status));
	sentenceBuffer.clear();
}

void TextThread::AddSentence(std::wstring sentence)
{
	TT_LOCK;
	sentence.append(L"\r\n");
	if (output) output(this, sentence);
	storage.append(sentence);
}

void TextThread::AddText(const BYTE *con, int len)
{
	TT_LOCK;
	sentenceBuffer.insert(sentenceBuffer.end(), con, con + len);
	SetTimer(dummyWindow, (UINT_PTR)this, splitDelay,
		[](HWND hWnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
	{
		KillTimer(hWnd, idEvent);
		((TextThread*)idEvent)->AddSentence();
	});
}

// EOF

// textthread.cc
// 8/24/2013 jichi
// Branch IHF/TextThread.cpp, rev 133
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "settings.h"
#include "textthread.h"
//#include "wintimer/wintimer.h"
#include "vnrhook/include/const.h"
#include "ithsys/ithsys.h"
#include <stdio.h>
#include "extensions/Extensions.h"

MK_BASIC_TYPE(BYTE)
MK_BASIC_TYPE(ThreadParameter)

static DWORD MIN_DETECT = 0x20;
static DWORD MIN_REDETECT = 0x80;
//#define MIN_DETECT    0x20
//#define MIN_REDETECT  0x80
#ifndef CURRENT_SELECT
# define CURRENT_SELECT        0x1000
#endif
#ifndef REPEAT_NUMBER_DECIDED
# define REPEAT_NUMBER_DECIDED  0x2000
#endif

DWORD GetHookName(LPSTR str, DWORD pid, DWORD hook_addr,DWORD max);

extern Settings *settings;
extern HWND dummyWindow;

TextThread::TextThread(ThreadParameter tp, WORD num) :
  //,tp
  thread_number(num)
  , output(nullptr)
  //, comment(nullptr)
  , status(0)
  , tp(tp)
  , sentenceBuffer()
{
}

void TextThread::Reset()
{
  MyVector::Reset();
}

void TextThread::AddSentence()
{
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
	sentence.append(L"\r\n\r\n");
	if (output) output(this, (const BYTE*)sentence.c_str(), sentence.length() * 2, false);
	AddToStore((const BYTE*)sentence.c_str(), sentence.length() * 2);
}

void TextThread::AddText(const BYTE *con, int len)
{
	sentenceBuffer.insert(sentenceBuffer.end(), con, con+len);
	SetTimer(dummyWindow, (UINT_PTR)this, settings->splittingInterval, 
		[](HWND hWnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) 
	{
		KillTimer(hWnd, idEvent);
		((TextThread*)idEvent)->AddSentence();
	});
}

void TextThread::GetEntryString(LPSTR buffer, DWORD max)
{
    int len = sprintf(buffer, "%.4X:%.4d:0x%08X:0x%08X:0x%08X:",
          thread_number, tp. pid, tp.hook, tp.retn, tp.spl);
    GetHookName(buffer + len, tp.pid, tp.hook, max - len);
}

// EOF

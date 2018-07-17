// textthread.cc
// 8/24/2013 jichi
// Branch IHF/TextThread.cpp, rev 133
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "host.h"
#include "textthread.h"
//#include "wintimer/wintimer.h"
#include "vnrhook/include/const.h"
#include "vnrhook/include/types.h"
#include <stdio.h>
#include "extensions/Extensions.h"

extern HookManager* man;

DWORD GetHookName(LPSTR str, DWORD pid, DWORD hook_addr, DWORD max)
{
	if (!pid)
		return 0;

	DWORD len = 0;
	max--; //for '\0' magic marker.

		   //if (pid == 0) {
		   //  len = wcslen(HookNameInitTable[0]);
		   //  if (len >= max)
		   //    len = max;
		   //  memcpy(str, HookNameInitTable[0], len << 1);
		   //  str[len] = 0;
		   //  return len;
		   //}

		   //::man->LockProcessHookman(pid);
	ProcessRecord *pr = ::man->GetProcessRecord(pid);
	if (!pr)
		return 0;
	WaitForSingleObject(pr->hookman_mutex, 0);
	const OldHook *hks = (const OldHook *)pr->hookman_map;
	for (int i = 0; i < MAX_HOOK; i++)
		if (hks[i].Address() == hook_addr) {
			len = hks[i].NameLength();
			if (len >= max)
				len = max;
			ReadProcessMemory(pr->process_handle, hks[i].Name(), str, len, &len);
			if (str[len - 1] == 0)
				len--;
			else
				str[len] = 0;
			break;
		}

	ReleaseMutex(pr->hookman_mutex);
	//::man->UnlockProcessHookman(pid);
	return len;
}

extern HWND dummyWindow;

TextThread::TextThread(ThreadParameter tp, unsigned int threadNumber, unsigned int splitDelay) :
  thread_number(threadNumber),
  splitDelay(splitDelay),
  output(nullptr),
  status(0),
  tp(tp),
  sentenceBuffer()
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
	sentence.append(L"\r\n");
	if (output) output(this, (const BYTE*)sentence.c_str(), sentence.length() * 2, false);
	AddToStore((const BYTE*)sentence.c_str(), sentence.length() * 2);
}

void TextThread::AddText(const BYTE *con, int len)
{
	sentenceBuffer.insert(sentenceBuffer.end(), con, con+len);
	SetTimer(dummyWindow, (UINT_PTR)this, splitDelay, 
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

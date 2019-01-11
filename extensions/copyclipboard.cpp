#include "extension.h"

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["current select"] && sentenceInfo["process id"] != 0)
	{
		if (!OpenClipboard(FindWindowW(NULL, L"Textractor"))) return false;
		HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (sentence.size() + 2) * sizeof(wchar_t));
		memcpy(GlobalLock(hMem), sentence.c_str(), (sentence.size() + 2) * sizeof(wchar_t));
		EmptyClipboard();
		SetClipboardData(CF_UNICODETEXT, hMem);
		GlobalUnlock(hMem);
		CloseClipboard();
	}
	return false;
}

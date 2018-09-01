#include "extensions.h"

bool ProcessSentence(std::wstring& sentence, const InfoForExtension* miscInfo)
{
	if (GetProperty("current select", miscInfo) && GetProperty("hook address", miscInfo) != -1)
	{
		HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (sentence.size() + 2) * sizeof(wchar_t));
		memcpy(GlobalLock(hMem), sentence.c_str(), (sentence.size() + 2) * sizeof(wchar_t));
		GlobalUnlock(hMem);
		OpenClipboard(0);
		EmptyClipboard();
		SetClipboardData(CF_UNICODETEXT, hMem);
		CloseClipboard();
	}
	return false;
}
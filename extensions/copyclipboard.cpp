#include "extensions.h"

extern "C"
{
	/**
	* Param sentence: pointer to sentence received by NextHooker (UTF-16).
	* You should not modify this sentence. If you want NextHooker to receive a modified sentence, copy it into your own buffer and return that.
	* Param miscInfo: pointer to start of singly linked list containing misc info about the sentence.
	* Return value: pointer to sentence NextHooker takes for future processing and display.
	* Return 'sentence' unless you created a new sentence/buffer as mentioned above.
	* NextHooker will display the sentence after all extensions have had a chance to process and/or modify it.
	* THIS FUNCTION MAY BE RUN SEVERAL TIMES CONCURRENTLY: PLEASE ENSURE THAT IT IS THREAD SAFE!
	*/
	__declspec(dllexport) const wchar_t* OnNewSentence(const wchar_t* sentence, const InfoForExtension* miscInfo)
	{
		if (GetProperty("current select", miscInfo) && GetProperty("hook address", miscInfo) != -1)
		{
			HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (wcslen(sentence) + 1) * sizeof(wchar_t));
			memcpy(GlobalLock(hMem), sentence, (wcslen(sentence) + 1) * sizeof(wchar_t));
			GlobalUnlock(hMem);
			OpenClipboard(0);
			EmptyClipboard();
			SetClipboardData(CF_UNICODETEXT, hMem);
			CloseClipboard();
		}
		return sentence;
	}
}
#include "extension.h"

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo);

/**
	* You shouldn't mess with this or even look at it unless you're certain you know what you're doing.
	* Param sentence: pointer to sentence received by Textractor (UTF-16).
	* You should not modify this sentence. If you want Textractor to receive a modified sentence, copy it into your own buffer and return that.
	* Please allocate the buffer using HeapAlloc() and not new[] or malloc() or something else: Textractor uses HeapFree() to free it.
	* Param miscInfo: pointer to start of singly linked list containing misc info about the sentence.
	* Return value: pointer to sentence Textractor takes for future processing and display. If nullptr, Textractor will destroy the sentence.
	* Return 'sentence' unless you created a new sentence/buffer as mentioned above.
	* Textractor will display the sentence after all extensions have had a chance to process and/or modify it.
	* THIS FUNCTION MAY BE RUN SEVERAL TIMES CONCURRENTLY: PLEASE ENSURE THAT IT IS THREAD SAFE!
*/
extern "C" __declspec(dllexport) const wchar_t* OnNewSentence(const wchar_t* sentence, const InfoForExtension* miscInfo)
{
	try
	{
		std::wstring sentenceStr(sentence);
		if (ProcessSentence(sentenceStr, SentenceInfo{ miscInfo }))
		{
			// No need to worry about freeing this: Textractor does it for you.
			wchar_t* newSentence = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (sentenceStr.size() + 1) * sizeof(wchar_t));
			wcscpy_s(newSentence, sentenceStr.size() + 1, sentenceStr.c_str());
			return newSentence;
		}
		else return sentence;
	}
	catch (SKIP) { return nullptr; }
}

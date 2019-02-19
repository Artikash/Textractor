#include "extension.h"

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo);

/**
	* You shouldn't mess with this or even look at it unless you're certain you know what you're doing.
	* Param sentence: pointer to sentence received by Textractor (UTF-16).
	* This can be modified. Textractor uses the modified sentence for future processing and display. If empty (starts with null terminator), Textractor will destroy it.
	* Textractor will display the sentence after all extensions have had a chance to process and/or modify it.
	* The buffer is allocated using HeapAlloc(). If you want to make it larger, please use HeapReAlloc().
	* Param miscInfo: pointer to array containing misc info about the sentence. End of array is marked with name being nullptr.
	* Return value: the buffer used for the sentence. Remember to return a new pointer if HeapReAlloc() gave you one.
	* THIS FUNCTION MAY BE RUN SEVERAL TIMES CONCURRENTLY: PLEASE ENSURE THAT IT IS THREAD SAFE!
*/
extern "C" __declspec(dllexport) wchar_t* OnNewSentence(wchar_t* sentence, const InfoForExtension* miscInfo)
{
	try
	{
		std::wstring sentenceStr(sentence);
		int origLength = sentenceStr.size();
		if (ProcessSentence(sentenceStr, SentenceInfo{ miscInfo }))
		{
			if (sentenceStr.size() > origLength) sentence = (wchar_t*)HeapReAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sentence, (sentenceStr.size() + 1) * sizeof(wchar_t));
			wcscpy_s(sentence, sentenceStr.size() + 1, sentenceStr.c_str());
		}
	}
	catch (SKIP)
	{
		*sentence = L'\0';
	}
	return sentence;
}

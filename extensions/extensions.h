#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <string>

struct InfoForExtension
{
	const char* name;
	int64_t value;
	InfoForExtension* next;
};

struct SentenceInfo
{
	const InfoForExtension* list;
	// Traverse linked list to find info.
	int64_t operator[](std::string propertyName)
	{
		for (auto i = list; i != nullptr; i = i->next) if (propertyName == i->name) return i->value;
		return 0;
	}
};

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo);

/**
	* You shouldn't mess with this or even look at it unless you're certain you know what you're doing.
	* Param sentence: pointer to sentence received by Textractor (UTF-16).
	* You should not modify this sentence. If you want Textractor to receive a modified sentence, copy it into your own buffer and return that.
	* Please allocate the buffer using malloc() and not new[] or something else: Textractor uses free() to free it.
	* Param miscInfo: pointer to start of singly linked list containing misc info about the sentence.
	* Return value: pointer to sentence Textractor takes for future processing and display.
	* Return 'sentence' unless you created a new sentence/buffer as mentioned above.
	* Textractor will display the sentence after all extensions have had a chance to process and/or modify it.
	* THIS FUNCTION MAY BE RUN SEVERAL TIMES CONCURRENTLY: PLEASE ENSURE THAT IT IS THREAD SAFE!
*/
extern "C" __declspec(dllexport) const wchar_t* OnNewSentence(const wchar_t* sentenceArr, const InfoForExtension* miscInfo)
{
	std::wstring sentence(sentenceArr);
	if (ProcessSentence(sentence, SentenceInfo{ miscInfo }))
	{
		// No need to worry about freeing this: Textractor does it for you.
		wchar_t* newSentence = (wchar_t*)malloc((sentence.size() + 1) * sizeof(wchar_t*));
		wcscpy_s(newSentence, sentence.size() + 1, sentence.c_str());
		return newSentence;
	}
	else return sentenceArr;
}

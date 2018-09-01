#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

struct InfoForExtension
{
	const char* propertyName;
	int propertyValue;
	InfoForExtension* nextProperty;
};

// Traverses linked list to find info.
int GetProperty(const char* propertyName, const InfoForExtension* miscInfo)
{
	const InfoForExtension* miscInfoTraverser = miscInfo;
	while (miscInfoTraverser != nullptr)
		if (strcmp(propertyName, miscInfoTraverser->propertyName) == 0) return miscInfoTraverser->propertyValue;
		else miscInfoTraverser = miscInfoTraverser->nextProperty;

	return 0;
}

/**
	* Param sentence: entence received by NextHooker (UTF-16).
	* Param miscInfo: pointer to start of singly linked list containing misc info about the sentence.
	* Return value: whether the sentence was modified.
	* NextHooker will display the sentence after all extensions have had a chance to process and/or modify it.
	* THIS FUNCTION MAY BE RUN SEVERAL TIMES CONCURRENTLY: PLEASE ENSURE THAT IT IS THREAD SAFE!
*/
bool ProcessSentence(std::wstring& sentence, const InfoForExtension* miscInfo);

/**
	* Param sentence: pointer to sentence received by NextHooker (UTF-16).
	* You should not modify this sentence. If you want NextHooker to receive a modified sentence, copy it into your own buffer and return that.
	* Param miscInfo: pointer to start of singly linked list containing misc info about the sentence.
	* Return value: pointer to sentence NextHooker takes for future processing and display.
	* Return 'sentence' unless you created a new sentence/buffer as mentioned above.
	* NextHooker will display the sentence after all extensions have had a chance to process and/or modify it.
	* THIS FUNCTION MAY BE RUN SEVERAL TIMES CONCURRENTLY: PLEASE ENSURE THAT IT IS THREAD SAFE!
*/
extern "C" __declspec(dllexport) const wchar_t* OnNewSentence(const wchar_t* sentenceArr, const InfoForExtension* miscInfo)
{
	std::wstring sentence(sentenceArr);
	if (ProcessSentence(sentence, miscInfo))
	{
		wchar_t* newSentence = (wchar_t*)malloc((sentence.size() + 1) * sizeof(wchar_t*));
		wcscpy(newSentence, sentence.c_str());
		return newSentence;
	}
	else return sentenceArr;
}
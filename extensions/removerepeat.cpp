#include "extensions.h"
#include <algorithm>
#include <cwctype>

std::wstring remove_side_spaces(const std::wstring& str)
{
	auto begin = std::find_if_not(str.begin(), str.end(), std::iswspace);
	if (begin == str.end()) return L"";
	auto end = std::find_if_not(str.rbegin(), str.rend(), std::iswspace);
	return std::wstring(begin, end.base());
}

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
		std::wstring sentenceStr = remove_side_spaces(std::wstring(sentence));
		unsigned long repeatNumber = 0;
		wchar_t prevChar = sentenceStr[0];
		for (auto i : sentenceStr)
			if (i == prevChar) repeatNumber++;
			else break;

		for (int i = 0; i < sentenceStr.size(); i += repeatNumber)
			for (int j = i; j < sentenceStr.size(); ++j)
				if (sentenceStr[j] != sentenceStr[i])
					if ((j - i) % repeatNumber != 0) return sentence;
					else break;

		if (repeatNumber == 1) return sentence;
		sentenceStr.erase(std::remove_if(sentenceStr.begin(), sentenceStr.end(), [&](const wchar_t& c) {return (&c - &*sentenceStr.begin()) % repeatNumber != 0; }), sentenceStr.end());

		wchar_t* newSentence = (wchar_t*)malloc((sentenceStr.size() + 2) * sizeof(wchar_t));
		wcscpy(newSentence, sentenceStr.c_str());
		return newSentence;
	}
}
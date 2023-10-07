#include "extension.h"

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (!sentenceInfo["current select"] || sentenceInfo["text number"] == 0) return false;

	static std::wstring prevSentence;

	std::wstring checkSentence = prevSentence;
	prevSentence = sentence;



	if (sentence.substr(0, checkSentence.size()) == checkSentence)
	{
		auto Ltrim = [](std::wstring& text)
		{
			text.erase(text.begin(), std::find_if_not(text.begin(), text.end(), iswspace));
		};

		sentence = sentence.substr(checkSentence.size());
		Ltrim(sentence);
		return true;
	}
	return false;
}

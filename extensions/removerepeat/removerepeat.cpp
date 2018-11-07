#include "../extension.h"

void RemoveRepeatedChars(std::wstring& sentence)
{
	int repeatNumber = 0;
	wchar_t prevChar = sentence[0];
	for (auto c : sentence)
		if (c == prevChar) repeatNumber++;
		else break;
	if (repeatNumber == 1) return;

	for (int i = 0; i < sentence.size(); i += repeatNumber)
		for (int j = i; j < sentence.size(); ++j)
			if (sentence[j] != sentence[i])
				if ((j - i) % repeatNumber != 0) return;
				else break;

	std::wstring newSentence = L"";
	for (int i = 0; i < sentence.size(); i += repeatNumber) newSentence.push_back(sentence[i]);
	sentence = newSentence;
}

void RemoveCyclicRepeats(std::wstring& sentence)
{
	for (std::wsmatch results; std::regex_search(sentence, results, std::wregex(L"^([^\\x00]{5,})[^\\x00]*?\\1")); sentence.erase(0, results[1].length()));
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["hook address"] == -1) return false;
	RemoveRepeatedChars(sentence);
	RemoveCyclicRepeats(sentence);
	return true;
}

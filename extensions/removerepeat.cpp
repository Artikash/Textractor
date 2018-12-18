#include "extension.h"

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
remove:
	for (std::wstring junk = sentence; junk.size() > 4; junk.pop_back())
		if (sentence.rfind(junk) > 0)
		{
			sentence.erase(0, junk.size());
			goto remove;
		}
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["hook address"] == -1) return false;
	RemoveRepeatedChars(sentence);
	RemoveCyclicRepeats(sentence);
	return true;
}

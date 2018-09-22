#include "extensions.h"
#include <set>
#include <mutex>

bool RemoveRepeatedChars(std::wstring& sentence)
{
	unsigned int repeatNumber = 0;
	wchar_t prevChar = sentence[0];
	for (auto i : sentence)
		if (i == prevChar) repeatNumber++;
		else break;
	if (repeatNumber == 1) return false;

	for (int i = 0; i < sentence.size(); i += repeatNumber)
		for (int j = i; j < sentence.size(); ++j)
			if (sentence[j] != sentence[i])
				if ((j - i) % repeatNumber != 0) return false;
				else break;

	std::wstring newSentence = L"";
	for (int i = 0; i < sentence.size(); ++i) if (i % repeatNumber == 0) newSentence.push_back(sentence[i]);
	sentence = newSentence;
	return true;
}

bool RemoveCyclicRepeats(std::wstring& sentence)
{
	unsigned int junkLength = 0;
	wchar_t junk[2000] = {};
	while (wcsstr(sentence.c_str() + junkLength, junk))
	{
		junk[junkLength] = sentence[junkLength];
		if (++junkLength >= 2000) return false;
	}
	if (--junkLength >= 5) // If the first 5 characters appear later on, there's probably a repetition issue.
	{
		sentence = std::wstring(sentence.c_str() + junkLength);
		RemoveCyclicRepeats(sentence);
		return true;
	}
	return false;
}

bool RemoveRepeatedSentences(std::wstring& sentence, int handle)
{
	static std::set<std::pair<int, std::wstring>> seenSentences;
	static std::mutex m;
	std::lock_guard<std::mutex> l(m);
	if (seenSentences.count({ handle, sentence }) != 0) throw std::exception();
	seenSentences.insert({ handle, sentence });
	return false;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["hook address"] == -1) return false;
	bool ret = false;
	ret |= RemoveRepeatedChars(sentence);
	ret |= RemoveCyclicRepeats(sentence);
	ret |= RemoveRepeatedSentences(sentence, sentenceInfo["text handle"]);
	return ret;
}
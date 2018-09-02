#include "extensions.h"
#include <set>
#include <mutex>
#include <algorithm>

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

	// Removes every repeatNumber'th character.
	sentence.erase(std::remove_if(sentence.begin(), sentence.end(), [&](const wchar_t& c) {return (&c - &*sentence.begin()) % repeatNumber != 0; }), sentence.end());
	return true;
}

bool RemoveCyclicRepeats(std::wstring& sentence)
{
	unsigned int realLength = 6; // If the first 6 characters appear later on, there's probably a repetition issue.
	if (sentence.size() < realLength) return false;
	wchar_t realSentence[2000] = {};
	memcpy(realSentence, sentence.c_str(), realLength * sizeof(wchar_t));
	while (wcsstr(sentence.c_str() + realLength, realSentence))
	{
		realSentence[realLength] = sentence[realLength];
		if (++realLength >= 2000) return false;
	}
	if (realLength > 7)
	{
		sentence = std::wstring(realSentence);
		RemoveCyclicRepeats(sentence);
		return true;
	}
	return false;
}

bool RemoveRepeatedSentences(std::wstring& sentence, int threadHandle)
{
	static std::set<std::pair<int, std::wstring>> seenSentences;
	static std::mutex m;
	std::lock_guard<std::mutex> l(m);
	if (seenSentences.count({ threadHandle, sentence }) != 0) throw std::exception();
	seenSentences.insert({ threadHandle, sentence });
	return false;
}

bool ProcessSentence(std::wstring& sentence, const InfoForExtension* miscInfo)
{
	if (GetProperty("hook address", miscInfo) == -1) return false;
	return RemoveRepeatedChars(sentence) | RemoveCyclicRepeats(sentence) | RemoveRepeatedSentences(sentence, GetProperty("text handle", miscInfo));
}
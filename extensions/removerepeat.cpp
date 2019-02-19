#include "extension.h"

void RemoveRepeatedChars(std::wstring& sentence)
{
	std::vector<int> repeatNumbers(sentence.size() + 1, 0);
	int repeatNumber = 1;
	wchar_t prevChar = L'\0';
	for (auto nextChar : sentence)
		if (nextChar == prevChar) repeatNumber++;
		else
		{
			prevChar = nextChar;
			++repeatNumbers.at(repeatNumber);
			repeatNumber = 1;
		}
	if ((repeatNumber = std::distance(repeatNumbers.begin(), std::max_element(repeatNumbers.begin(), repeatNumbers.end()))) == 1) return;

	std::wstring newSentence;
	for (int i = 0; i < sentence.size();)
	{
		newSentence.push_back(sentence.at(i));
		for (int j = i; j <= sentence.size(); ++j)
		{
			if (j == sentence.size() || sentence.at(i) != sentence.at(j))
			{
				i += (j - i) % repeatNumber == 0 ? repeatNumber : 1;
				break;
			}
		}
	}
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
	if (sentenceInfo["text number"] == 0) return false;
	RemoveRepeatedChars(sentence);
	RemoveCyclicRepeats(sentence);
	return true;
}

TEST(
	{
		std::wstring repeatedChars = L"aaaaaaaaaaaabbbbbbcccdddaabbbcccddd";
		RemoveRepeatedChars(repeatedChars);
		assert(repeatedChars.find(L"aaaabbcd") == 0);

		std::wstring cyclicRepeats = L"abcdeabcdefabcdefgabcdefgabcdefgabcdefgabcdefg";
		RemoveCyclicRepeats(cyclicRepeats);
		assert(cyclicRepeats == L"abcdefg");

		std::wstring empty = L"", one = L" ", normal = L"This is a normal sentence. はい";
		ProcessSentence(empty, { SentenceInfo::DUMMY });
		ProcessSentence(one, { SentenceInfo::DUMMY });
		ProcessSentence(normal, { SentenceInfo::DUMMY });
		assert(empty == L"" && one == L" " && normal == L"This is a normal sentence. はい");
	}
);

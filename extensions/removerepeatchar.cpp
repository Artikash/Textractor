#include "extension.h"

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0) return false;

	std::vector<int> repeatNumbers(sentence.size() + 1, 0);
	int repeatNumber = 1;
	wchar_t prevChar = L'\0';
	for (auto nextChar : sentence)
	{
		if (nextChar == prevChar)
		{
			repeatNumber += 1;
		}
		else
		{
			prevChar = nextChar;
			repeatNumbers.at(repeatNumber) += 1;
			repeatNumber = 1;
		}
	}
	if ((repeatNumber = std::distance(repeatNumbers.begin(), std::max_element(repeatNumbers.begin(), repeatNumbers.end()))) == 1) return false;

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
	return true;
}

TEST(
	{
		std::wstring repeatedChars = L"aaaaaaaaaaaabbbbbbcccdddaabbbcccddd";
		ProcessSentence(repeatedChars, { SentenceInfo::DUMMY });
		assert(repeatedChars.find(L"aaaabbcd") == 0);

		std::wstring empty = L"", one = L" ", normal = L"This is a normal sentence. はい";
		ProcessSentence(empty, { SentenceInfo::DUMMY });
		ProcessSentence(one, { SentenceInfo::DUMMY });
		ProcessSentence(normal, { SentenceInfo::DUMMY });
		assert(empty == L"" && one == L" " && normal == L"This is a normal sentence. はい");
	}
);

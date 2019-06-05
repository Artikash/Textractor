#include "extension.h"

void RemoveRepeatedSentences(std::wstring& sentence, uint64_t textNumber)
{
	static std::deque<Synchronized<std::vector<std::wstring>>> cache;
	static std::mutex m;
	m.lock();
	if (textNumber + 1 > cache.size()) cache.resize(textNumber + 1);
	auto prevSentences = cache.at(textNumber).Acquire();
	m.unlock();
	auto& inserted = prevSentences->emplace_back(sentence);
	auto firstLocation = std::find(prevSentences->begin(), prevSentences->end(), sentence);
	if (&*firstLocation != &inserted)
	{
		prevSentences->erase(firstLocation);
		sentence.clear();
	}
	if (prevSentences->size() > 50) prevSentences->erase(prevSentences->begin());
}

void RemoveRepeatedChars(std::wstring& sentence)
{
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
	if (sentence.size() > 15000) return; // this algorithm is O(N^3) so if N > 15000 it's extremely slow
	auto data = std::make_unique<wchar_t[]>(sentence.size() + 1);
	wcscpy_s(data.get(), sentence.size() + 1, sentence.c_str());
	wchar_t* dataEnd = data.get() + sentence.size();
	int skip = 0, count = 0;
	for (wchar_t* end = dataEnd; end - data.get() > skip; --end)
	{
		std::swap(*end, *dataEnd);
		int junkLength = end - data.get() - skip;
		auto junkFound = wcsstr(sentence.c_str() + skip + junkLength, data.get() + skip);
		std::swap(*end, *dataEnd);
		if (junkFound)
		{
			if (count && junkLength < min(skip / count, 4)) break;
			skip += junkLength;
			count += 1;
			end = dataEnd;
		}
	}
	if (count && skip / count >= 3) sentence = data.get() + skip;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0) return false;
	RemoveRepeatedSentences(sentence, sentenceInfo["text number"]);
	RemoveRepeatedChars(sentence);
	RemoveCyclicRepeats(sentence);
	return true;
}

TEST(
	{
		std::wstring repeatedChars = L"aaaaaaaaaaaabbbbbbcccdddaabbbcccddd";
		RemoveRepeatedChars(repeatedChars);
		assert(repeatedChars.find(L"aaaabbcd") == 0);

		std::wstring cyclicRepeats = L"_abcde_abcdef_abcdefg_abcdefg_abcdefg_abcdefg_abcdefg";
		std::wstring buildupRepeats = L"__a_ab_abc_abcd_abcde_abcdef_abcdefg";
		RemoveCyclicRepeats(cyclicRepeats);
		RemoveCyclicRepeats(buildupRepeats);
		assert(cyclicRepeats == L"_abcdefg");
		assert(buildupRepeats == L"_abcdefg");

		std::wstring empty = L"", one = L" ", normal = L"This is a normal sentence. はい";
		ProcessSentence(empty, { SentenceInfo::DUMMY });
		ProcessSentence(one, { SentenceInfo::DUMMY });
		ProcessSentence(normal, { SentenceInfo::DUMMY });
		assert(empty == L"" && one == L" " && normal == L"This is a normal sentence. はい");
	}
);

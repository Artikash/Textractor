#include "extension.h"

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0) return false;

	if (sentence.size() > 15000) return false; // this algorithm is O(N^3) so if N > 15000 it's extremely slow
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
	if (count && skip / count >= 3)
	{
		sentence = data.get() + skip;
		return true;
	}
	return false;
}

TEST(
	{
		std::wstring cyclicRepeats = L"_abcde_abcdef_abcdefg_abcdefg_abcdefg_abcdefg_abcdefg";
		std::wstring buildupRepeats = L"__a_ab_abc_abcd_abcde_abcdef_abcdefg";
		ProcessSentence(cyclicRepeats, { SentenceInfo::DUMMY });
		ProcessSentence(buildupRepeats, { SentenceInfo::DUMMY });
		assert(cyclicRepeats == L"_abcdefg");
		assert(buildupRepeats == L"_abcdefg");

		std::wstring empty = L"", one = L" ", normal = L"This is a normal sentence. はい";
		ProcessSentence(empty, { SentenceInfo::DUMMY });
		ProcessSentence(one, { SentenceInfo::DUMMY });
		ProcessSentence(normal, { SentenceInfo::DUMMY });
		assert(empty == L"" && one == L" " && normal == L"This is a normal sentence. はい");
	}
);

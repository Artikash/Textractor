#include "extension.h"

constexpr wchar_t ERASED = 0xe012; // inside Unicode private use area

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0) return false;

	// This algorithm looks for repeating substrings (in other words, common prefixes among the set of suffixes) of the sentence with length > 6
	// It then looks for any regions of characters at least twice as long as the substring made up only of characters in the substring, and erases them
	// If this results in the common prefix being completely erased from the string, the common prefix is copied to the last location where it was located in the original string
	std::vector<int> suffixArray(sentence.size());
	for (int i = 0; i < sentence.size(); ++i) suffixArray[i] = i;
	std::sort(suffixArray.begin(), suffixArray.end(), [&](int a, int b) { return wcsncmp(sentence.c_str() + a, sentence.c_str() + b, 5000) > 0; });
	for (int i = 0; i + 1 < sentence.size(); ++i)
	{
		int commonPrefixLength = 0;
		for (int j = suffixArray[i], k = suffixArray[i + 1]; j < sentence.size() && k < sentence.size(); ++j, ++k)
			if (sentence[j] != ERASED && sentence[k] != ERASED && sentence[j] == sentence[k]) commonPrefixLength += 1;
			else break;

		if (commonPrefixLength > 6)
		{
			std::wstring commonPrefixCopy(sentence.c_str() + suffixArray[i], commonPrefixLength);
			std::unordered_set<wchar_t, Identity<wchar_t>> commonPrefixChars(commonPrefixCopy.begin(), commonPrefixCopy.end());

			for (int regionSize = 0, j = 0; j <= sentence.size(); ++j)
				if (commonPrefixChars.find(sentence[j]) != commonPrefixChars.end()) regionSize += 1;
				else if (regionSize >= commonPrefixLength * 2)
					while (regionSize > 0)
						sentence[j - regionSize--] = ERASED;
				else regionSize = 0;

			if (!wcsstr(sentence.c_str(), commonPrefixCopy.c_str()))
				std::copy(commonPrefixCopy.begin(), commonPrefixCopy.end(), sentence.data() + max(suffixArray[i], suffixArray[i + 1]));
		}
	}
	sentence.erase(std::remove(sentence.begin(), sentence.end(), ERASED), sentence.end());
	return true;
}

TEST(
	{
		std::wstring cyclicRepeats = L"Name: '_abcdefg_abcdefg_abcdefg_abcdefg_abcdefg'";
		std::wstring buildupRepeats = L"Name: '__a_ab_abc_abcd_abcde_abcdef_abcdefg'";
		std::wstring breakdownRepeats = L"Name: '_abcdefg_abcdef_abcde_abcd_abc_ab_a_'";
		ProcessSentence(cyclicRepeats, { SentenceInfo::DUMMY });
		ProcessSentence(buildupRepeats, { SentenceInfo::DUMMY });
		ProcessSentence(breakdownRepeats, { SentenceInfo::DUMMY });
		assert(cyclicRepeats == L"Name: '_abcdefg'");
		assert(buildupRepeats == L"Name: '_abcdefg'");
		assert(breakdownRepeats == L"Name: '_abcdefg'");

		std::wstring empty = L"", one = L" ", normal = L"This is a normal sentence. はい";
		ProcessSentence(empty, { SentenceInfo::DUMMY });
		ProcessSentence(one, { SentenceInfo::DUMMY });
		ProcessSentence(normal, { SentenceInfo::DUMMY });
		assert(empty == L"" && one == L" " && normal == L"This is a normal sentence. はい");
	}
);

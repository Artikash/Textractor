#include "extension.h"

constexpr wchar_t ERASED = 0xe012; // inside Unicode private use area

std::vector<int> GenerateSuffixArray(const std::wstring& text)
{
	std::vector<int> identity(text.size());
	for (int i = 0; i < text.size(); ++i) identity[i] = i;
	std::vector<int> suffixArray = identity;
	// The below code is a more efficient way of doing this:
	// std::sort(suffixArray.begin(), suffixArray.end(), [&](int a, int b) { return wcscmp(text.c_str() + a, text.c_str() + b) > 0; });
	std::stable_sort(suffixArray.begin(), suffixArray.end(), [&](int a, int b) { return text[a] > text[b]; });
	std::vector<int> classes(text.begin(), text.end());
	for (int length = 1; length < text.size(); length *= 2)
	{
		// Determine equivalence class up to length, by checking length/2 equivalence of suffixes and their following length/2 suffixes
		std::vector<int> oldClasses = classes;
		classes[suffixArray[0]] = 0;
		for (int i = 1; i < text.size(); ++i)
		{
			int currentSuffix = suffixArray[i];
			int lastSuffix = suffixArray[i - 1];
			if (currentSuffix + length < text.size() && oldClasses[currentSuffix] == oldClasses[lastSuffix] &&
				oldClasses[currentSuffix + length / 2] == oldClasses.at(lastSuffix + length / 2)) // not completely certain that this will stay in range
				classes[currentSuffix] = classes[lastSuffix];
			else classes[currentSuffix] = i;
		}

		// Sort within equivalence class based on order of following suffix after length
		// Orders up to length*2
		std::vector<int> count = identity;
		for (auto suffix : std::vector(suffixArray))
		{
			int precedingSuffix = suffix - length;
			if (precedingSuffix >= 0) suffixArray[count[classes[precedingSuffix]]++] = precedingSuffix;
		}
	}
	for (int i = 0; i + 1 < text.size(); ++i)
		assert(wcscmp(text.c_str() + suffixArray[i], text.c_str() + suffixArray[i + 1]) > 0);
	return suffixArray;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0) return false;

	// This algorithm looks for repeating substrings (in other words, common prefixes among the set of suffixes) of the sentence with length > 6
	// It then looks for any regions of characters at least twice as long as the substring made up only of characters in the substring, and erases them
	// If this results in the common prefix being completely erased from the string, the common prefix is copied to the last location where it was located in the original string
	std::vector<int> suffixArray = GenerateSuffixArray(sentence);
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

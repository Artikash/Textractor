#include "extension.h"
#include "blockmarkup.h"
#include <cwctype>
#include <fstream>
#include <sstream>
#include <process.h>

extern const wchar_t* REPLACER_INSTRUCTIONS;
extern const wchar_t* REPOSITORY;

constexpr auto REPLACE_SAVE_FILE = L"SavedReplacements.txt";

std::wstring  replaceSaveFile;
std::wstring  currConfigFolder;

std::atomic<std::filesystem::file_time_type> replaceFileLastWrite = {};
concurrency::reader_writer_lock m;

class Trie
{
public:
	Trie(const std::istream& replacementScript)
	{
		BlockMarkupIterator replacementScriptParser(replacementScript, Array<std::wstring_view>{ L"|ORIG|", L"|BECOMES|" });
		while (auto read = replacementScriptParser.Next())
		{
			const auto& [original, replacement] = read.value();
			Node* current = &root;
			for (auto ch : original) if (!Ignore(ch)) current = Next(current, ch);
			if (current != &root)
				current->value = charStorage.insert(charStorage.end(), replacement.c_str(), replacement.c_str() + replacement.size() + 1) - charStorage.begin();
		}
	}

	std::wstring Replace(const std::wstring& sentence) const
	{
		std::wstring result;
		for (int i = 0; i < sentence.size();)
		{
			std::wstring_view replacement(sentence.c_str() + i, 1);
			int originalLength = 1;

			const Node* current = &root;
			for (int j = i; current && j <= sentence.size(); ++j)
			{
				if (current->value >= 0)
				{
					replacement = charStorage.data() + current->value;
					originalLength = j - i;
				}
				if (!Ignore(sentence[j])) current = Next(current, sentence[j]) ? Next(current, sentence[j]) : Next(current, L'^');
			}

			result += replacement;
			i += originalLength;
		}
		return result;
	}

	bool Empty()
	{
		return root.charMap.empty();
	}

	void Clear()
	{
		root.charMap.clear();
	}

private:
	static bool Ignore(wchar_t ch)
	{
		return ch <= 0x20 || iswspace(ch);
	}

	template <typename Node>
	static Node* Next(Node* node, wchar_t ch)
	{
		auto it = std::lower_bound(node->charMap.begin(), node->charMap.end(), ch, [](const auto& one, auto two) { return one.first < two; });
		if (it != node->charMap.end() && it->first == ch) return it->second.get();
		if constexpr (!std::is_const_v<Node>) return node->charMap.insert(it, { ch, std::make_unique<Node>() })->second.get();
		return nullptr;
	}

	struct Node
	{
		std::vector<std::pair<wchar_t, std::unique_ptr<Node>>> charMap;
		ptrdiff_t value = -1;
	} root;

	std::vector<wchar_t> charStorage;
} trie = { std::istringstream("") };

void UpdateReplacements()
{
	try
	{
		if (replaceFileLastWrite.exchange(std::filesystem::last_write_time(replaceSaveFile)) == std::filesystem::last_write_time(replaceSaveFile)) return;
		std::scoped_lock lock(m);
		trie = Trie(std::ifstream(replaceSaveFile, std::ios::binary));
	}
	catch (std::filesystem::filesystem_error) { replaceFileLastWrite.store({}); }
}

void InitializeReplacements()
{
	if (!std::filesystem::exists(replaceSaveFile))
	{
		auto file = std::ofstream(replaceSaveFile, std::ios::binary) << "\xff\xfe";
		for (auto ch : std::wstring_view(REPLACER_INSTRUCTIONS))
			file << (ch == L'\n' ? std::string_view("\r\0\n", 4) : std::string_view((char*)&ch, 2));
		SpawnThread([] { _wspawnlp(_P_DETACH, L"notepad", L"notepad", replaceSaveFile.c_str(), NULL); }); // show file to user
	}
	trie.Clear();
	UpdateReplacements();
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (!sentenceInfo["current select"] || sentenceInfo["text number"] == 0) return false;

	wchar_t *configFolder = (wchar_t *)(sentenceInfo["config folder"]);
	if (configFolder == currConfigFolder)
		UpdateReplacements();
	else 
	{
		currConfigFolder = configFolder;
		replaceSaveFile = configFolder;
		replaceSaveFile += REPLACE_SAVE_FILE;
		InitializeReplacements();
	}

	concurrency::reader_writer_lock::scoped_lock_read readLock(m);
	sentence = trie.Replace(sentence);
	return true;
}


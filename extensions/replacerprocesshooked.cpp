#include "extension.h"
#include "blockmarkup.h"
#include <cwctype>
#include <fstream>
#include <sstream>
#include <process.h>
#include "module.h"

extern const wchar_t* REPLACER_INSTRUCTIONS;

std::wstring  replaceSaveFile;
std::wstring  currProcessName;

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
	UpdateReplacements();
	if (trie.Empty())
	{
		auto file = std::ofstream(replaceSaveFile, std::ios::binary) << "\xff\xfe";
		for (auto ch : std::wstring_view(REPLACER_INSTRUCTIONS))
			file << (ch == L'\n' ? std::string_view("\r\0\n", 4) : std::string_view((char*)&ch, 2));
		// I couldn't get it to work. Commented
		//_spawnlp(_P_DETACH, "notepad", "notepad", replaceSaveFile, NULL); // show file to user
	}
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (!sentenceInfo["current select"] || sentenceInfo["text number"] == 0) return false;

	if (auto processName = GetModuleFilename(sentenceInfo["process id"]))
	{
		if (currProcessName == processName.value())
			UpdateReplacements();
		else 
		{
			currProcessName = processName.value();
			// SavedReplacements_<directory name containing hocked process>.txt
			replaceSaveFile = FormatString(L"SavedReplacements_%ls.txt", FormatString(L"%ls", std::filesystem::path(currProcessName).parent_path().filename().c_str()));
			InitializeReplacements();
		}
	}
	else 
		return false;

	concurrency::reader_writer_lock::scoped_lock_read readLock(m);
	sentence = trie.Replace(sentence);
	return true;
}


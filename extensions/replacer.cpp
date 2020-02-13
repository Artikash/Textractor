#include "extension.h"
#include "trie.h"
#include "charstorage.h"
#include <cwctype>
#include <fstream>
#include <filesystem>
#include <process.h>

extern const wchar_t* REPLACER_INSTRUCTIONS;

constexpr auto REPLACE_SAVE_FILE = u8"SavedReplacements.txt";

std::atomic<std::filesystem::file_time_type> replaceFileLastWrite = {};
std::shared_mutex m;

class ReplacementTrie
{
public:
	ReplacementTrie(std::vector<std::pair<std::wstring, std::wstring>> replacements)
	{
		for (auto& [original, replacement] : replacements)
			if (!original.empty())
				trie.Insert(std::wstring_view(original.c_str(), std::remove_if(original.begin(), original.end(), Ignore) - original.begin()))->SetValue(storage.Store(replacement));
	}

	std::wstring Replace(const std::wstring& sentence) const
	{
		std::wstring result;
		for (int i = 0; i < sentence.size();)
		{
			std::wstring_view replacement(sentence.c_str() + i, 1);
			int originalLength = 1;

			auto current = trie.Root();
			for (int j = i; current && j <= sentence.size(); ++j)
			{
				if (const wchar_t* tail = current->Tail())
					for (; j <= sentence.size() && *tail; ++j)
						if (Ignore(sentence[j]));
						else if (sentence[j] == *tail) ++tail;
						else goto doneSearchingTrie;
				if (int* value = current->Value())
				{
					replacement = storage.Retrieve(*value);
					originalLength = j - i;
				}
				if (!Ignore(sentence[j])) current = trie.Next(current, sentence[j]);
			}
		
		doneSearchingTrie:
			result += replacement;
			i += originalLength;
		}
		return result;
	}

	bool Empty()
	{
		return trie.Root()->charMap.empty();
	}

private:
	static bool Ignore(wchar_t ch)
	{
		return ch <= 0x20 || std::iswspace(ch);
	}

	CharStorage<wchar_t> storage;
	Trie<wchar_t, int> trie;
} trie = { {} };

std::vector<std::pair<std::wstring, std::wstring>> Parse(std::wstring_view replacementScript)
{
	std::vector<std::pair<std::wstring, std::wstring>> replacements;
	for (size_t end = 0; ;)
	{
		size_t original = replacementScript.find(L"|ORIG|", end);
		size_t becomes = replacementScript.find(L"|BECOMES|", original);
		if ((end = replacementScript.find(L"|END|", becomes)) == std::wstring::npos) break;
		replacements.emplace_back(replacementScript.substr(original + 6, becomes - original - 6), replacementScript.substr(becomes + 9, end - becomes - 9));
	}
	return replacements;
}

void UpdateReplacements()
{
	try
	{
		if (replaceFileLastWrite.exchange(std::filesystem::last_write_time(REPLACE_SAVE_FILE)) == std::filesystem::last_write_time(REPLACE_SAVE_FILE)) return;
		std::vector<BYTE> file(std::istreambuf_iterator(std::ifstream(REPLACE_SAVE_FILE, std::ios::binary)), {});
		std::scoped_lock l(m);
		trie = ReplacementTrie(Parse({ (wchar_t*)file.data(), file.size() / sizeof(wchar_t) }));
	}
	catch (std::filesystem::filesystem_error) { replaceFileLastWrite.store({}); }
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		UpdateReplacements();
		if (trie.Empty())
		{
			auto file = std::ofstream(REPLACE_SAVE_FILE, std::ios::binary) << "\xff\xfe";
			for (auto ch : std::wstring_view(REPLACER_INSTRUCTIONS)) file <<  (ch == L'\n' ? std::string_view("\r\0\n", 4) : std::string_view((char*)&ch, 2));
			_spawnlp(_P_DETACH, "notepad", "notepad", REPLACE_SAVE_FILE, NULL); // show file to user
		}
	}
	break;
	case DLL_PROCESS_DETACH:
	{
	}
	break;
	}
	return TRUE;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo)
{
	UpdateReplacements();

	std::shared_lock l(m);
	sentence = trie.Replace(sentence);
	return true;
}

TEST(
	{
		auto replacements = Parse(LR"(
|ORIG|さよなら|BECOMES|goodbye |END|Ignore this text
And this text ツ　　
|ORIG|バカ|BECOMES|idiot|END|
|ORIG|こんにちは |BECOMES| hello|END||ORIG|delete this|BECOMES||END|)");
		assert(replacements.size() == 4);
		std::wstring original = LR"(Don't replace this　
 さよなら バカ こんにちは delete this)";
		std::wstring replaced = ReplacementTrie(std::move(replacements)).Replace(original);
		assert(replaced == L"Don't replace thisgoodbye idiot hello");
	}
);

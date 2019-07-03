#include "extension.h"
#include <cwctype>
#include <fstream>
#include <filesystem>
#include <process.h>

extern const wchar_t* REPLACER_INSTRUCTIONS;

constexpr auto REPLACE_SAVE_FILE = u8"SavedReplacements.txt";

std::atomic<std::filesystem::file_time_type> replaceFileLastWrite = {};
std::shared_mutex m;

class Trie
{
public:
	Trie(const std::unordered_map<std::wstring, std::wstring>& replacements)
	{
		for (const auto& [original, replacement] : replacements)
		{
			Node* current = &root;
			for (auto ch : original)
				if (Ignore(ch));
				else if (auto& next = current->next[ch]) current = next.get();
				else current = (next = std::make_unique<Node>()).get();
			if (current != &root) current->value = replacement;
		}
	}

	std::wstring Replace(const std::wstring& sentence) const
	{
		std::wstring result;
		for (int i = 0; i < sentence.size();)
		{
			std::wstring replacement(1, sentence[i]);
			int originalLength = 1;

			const Node* current = &root;
			for (int j = i; j < sentence.size() + 1; ++j)
			{
				if (current->value)
				{
					replacement = current->value.value();
					originalLength = j - i;
				}
				if (current->next.count(sentence[j]) > 0) current = current->next.at(sentence[j]).get();
				else if (Ignore(sentence[j]));
				else break;
			}

			result += replacement;
			i += originalLength;
		}
		return result;
	}

private:
	static bool Ignore(wchar_t ch)
	{
		return ch <= 0x20 || std::iswspace(ch);
	}

	struct Node
	{
		std::unordered_map<wchar_t, std::unique_ptr<Node>> next;
		std::optional<std::wstring> value;
	} root;
} trie = { {} };

std::unordered_map<std::wstring, std::wstring> Parse(const std::wstring& replacementScript)
{
	std::unordered_map<std::wstring, std::wstring> replacements;
	size_t end = 0;
	while (true)
	{
		size_t original = replacementScript.find(L"|ORIG|", end);
		size_t becomes = replacementScript.find(L"|BECOMES|", original);
		if ((end = replacementScript.find(L"|END|", becomes)) == std::wstring::npos) break;
		replacements[replacementScript.substr(original + 6, becomes - original - 6)] = replacementScript.substr(becomes + 9, end - becomes - 9);
	}
	return replacements;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		std::vector<BYTE> file(std::istreambuf_iterator<char>(std::ifstream(REPLACE_SAVE_FILE, std::ios::in | std::ios::binary)), {});
		if (Parse(std::wstring((wchar_t*)file.data(), file.size() / sizeof(wchar_t))).empty())
		{
			std::ofstream(REPLACE_SAVE_FILE, std::ios::out | std::ios::binary | std::ios::trunc).write((char*)REPLACER_INSTRUCTIONS, wcslen(REPLACER_INSTRUCTIONS) * sizeof(wchar_t));
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
	try
	{
		static_assert(std::has_unique_object_representations_v<decltype(replaceFileLastWrite)::value_type>);
		if (replaceFileLastWrite.exchange(std::filesystem::last_write_time(REPLACE_SAVE_FILE)) != std::filesystem::last_write_time(REPLACE_SAVE_FILE))
		{
			std::scoped_lock l(m);
			std::vector<BYTE> file(std::istreambuf_iterator<char>(std::ifstream(REPLACE_SAVE_FILE, std::ios::in | std::ios::binary)), {});
			trie = Trie(Parse(std::wstring((wchar_t*)file.data(), file.size() / sizeof(wchar_t))));
		}
	}
	catch (std::filesystem::filesystem_error) {}

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
		std::wstring replaced = Trie(replacements).Replace(original);
		assert(replaced == L"Don't replace thisgoodbye idiot hello");
	}
);

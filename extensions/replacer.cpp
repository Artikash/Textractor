#include "extension.h"
#include <cwctype>
#include <fstream>
#include <atomic>
#include <filesystem>
#include <process.h>

extern const wchar_t* REPLACER_INSTRUCTIONS;
constexpr auto REPLACE_SAVE_FILE = u8"SavedReplacements.txt";

std::atomic<std::filesystem::file_time_type> replaceFileLastWrite;

struct
{
public:
	void Put(std::wstring original, std::wstring replacement)
	{
		Node* current = &root;
		for (auto ch : original)
			if (Ignore(ch));
			else if (auto& next = current->next[ch]) current = next.get();
			else current = (next = std::make_unique<Node>()).get();
		if (current != &root) current->value = replacement;
	}

	std::pair<int, std::optional<std::wstring>> Lookup(const std::wstring& text)
	{
		std::pair<int, std::optional<std::wstring>> result = {};
		int length = 0;
		Node* current = &root;
		for (auto ch : text)
		{
			if (Ignore(ch))
			{
				length += 1;
			}
			else if (auto& next = current->next[ch])
			{
				length += 1;
				current = next.get();
				if (current->value) result = { length, current->value };
			}
			else break;
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
} replacementTrie;

int Parse(const std::wstring& file)
{
	replacementTrie = {};
	int count = 0;
	size_t end = 0;
	while (true)
	{
		size_t original = file.find(L"|ORIG|", end);
		size_t becomes = file.find(L"|BECOMES|", original);
		if ((end = file.find(L"|END|", becomes)) == std::wstring::npos) break;
		replacementTrie.Put(file.substr(original + 6, becomes - original - 6), file.substr(becomes + 9, end - becomes - 9));
		count += 1;
	}
	return count;
}

bool Replace(std::wstring& sentence)
{
	for (int i = 0; i < sentence.size(); ++i)
	{
		auto[length, replacement] = replacementTrie.Lookup(sentence.substr(i));
		if (replacement)
		{
			sentence.replace(i, length, replacement.value());
			i += replacement.value().size() - 1; // iterate to end of replacement
		}
	}
	return true;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	static HANDLE replacementFile; // not actually used to read/write, just to ensure it exists
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		replacementFile = CreateFileA(REPLACE_SAVE_FILE, FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		std::vector<BYTE> file(std::istreambuf_iterator<char>(std::ifstream(REPLACE_SAVE_FILE, std::ios::in | std::ios::binary)), {});
		if (Parse(std::wstring((wchar_t*)file.data(), file.size() / sizeof(wchar_t))) == 0)
		{
			std::ofstream(REPLACE_SAVE_FILE, std::ios::out | std::ios::binary | std::ios::trunc).write((char*)REPLACER_INSTRUCTIONS, wcslen(REPLACER_INSTRUCTIONS) * sizeof(wchar_t));
			_spawnlp(_P_DETACH, "notepad", "notepad", REPLACE_SAVE_FILE, NULL); // show file to user
		}
		replaceFileLastWrite = std::filesystem::last_write_time(REPLACE_SAVE_FILE);
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		CloseHandle(replacementFile);
	}
	break;
	}
	return TRUE;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo)
{
	static std::shared_mutex m;

	static_assert(std::has_unique_object_representations_v<decltype(replaceFileLastWrite)::value_type>);
	if (!replaceFileLastWrite.compare_exchange_strong(std::filesystem::last_write_time(REPLACE_SAVE_FILE), std::filesystem::last_write_time(REPLACE_SAVE_FILE)))
	{
		std::lock_guard l(m);
		std::vector<BYTE> file(std::istreambuf_iterator<char>(std::ifstream(REPLACE_SAVE_FILE, std::ios::in | std::ios::binary)), {});
		Parse(std::wstring((wchar_t*)file.data(), file.size() / sizeof(wchar_t)));
	}

	std::shared_lock l(m);
	return Replace(sentence);
}

TEST(
	{
		assert(Parse(LR"(|ORIG| さよなら|BECOMES|goodbye|END|
|ORIG|バカ|BECOMES|idiot|END|
|ORIG|こんにちは |BECOMES|hello|END|)") == 3);
		std::wstring replaced = LR"(blahblah　
 さよなら バカ こんにちは)";
		Replace(replaced);
		assert(replaced.find(L"さよなら") == std::wstring::npos &&
			replaced.find(L"バカ") == std::wstring::npos &&
			replaced.find(L"こんにちは") == std::wstring::npos &&
			replaced.find(L"goodbye") != std::wstring::npos &&
			replaced.find(L"idiot") != std::wstring::npos &&
			replaced.find(L"hello") != std::wstring::npos
		);
	}
);

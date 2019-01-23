#include "extension.h"
#include "defs.h"
#include "text.h"
#include <cwctype>
#include <fstream>

std::shared_mutex m;

struct
{
public:
	void Put(std::wstring original, std::wstring replacement)
	{
		Node* current = &root;
		for (auto c : original)
			if (Ignore(c));
			else if (auto& next = current->next[c]) current = next.get();
			else current = (next = std::make_unique<Node>()).get();
		current->value = replacement;
	}

	std::pair<int, std::wstring> Lookup(const std::wstring& text)
	{
		int length = 0;
		Node* current = &root;
		for (auto c : text)
			if (Ignore(c)) ++length;
			else if (auto& next = current->next[c]) ++length, current = next.get();
			else break;
		return { length, current->value };
	}

private:
	static bool Ignore(wchar_t c)
	{
		return c <= 0x20 || std::iswspace(c);
	}

	struct Node
	{
		std::unordered_map<wchar_t, std::unique_ptr<Node>> next;
		std::wstring value;
	} root;
} replacementTrie;

void Parse(const std::wstring& file)
{
	std::lock_guard l(m);
	size_t end = 0;
	while (true)
	{
		size_t original = file.find(L"|ORIG|", end);
		size_t becomes = file.find(L"|BECOMES|", original);
		end = file.find(L"|END|", becomes);
		if (end != std::wstring::npos) replacementTrie.Put(file.substr(original + 6, becomes - original - 6), file.substr(becomes + 9, end - becomes - 9));
		else break;
	}
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		std::vector<BYTE> file(std::istreambuf_iterator<char>(std::ifstream(REPLACE_SAVE_FILE, std::ios::binary)), {});
		Parse(std::wstring((wchar_t*)file.data(), file.size() / sizeof(wchar_t)));
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
	std::shared_lock l(m);
	for (int i = 0; i < sentence.size(); ++i)
		if (sentence.size() > 10000) return false; // defend against infinite looping
		else if (auto[length, replacement] = replacementTrie.Lookup(sentence.substr(i)); !replacement.empty()) sentence.replace(i, length, replacement);
	return true;
}

TEST(
	{
		Parse(LR"(|ORIG|さよなら|BECOMES|goodbye|END|
|ORIG|バカ|BECOMES|idiot|END|
|ORIG|こんにちは|BECOMES|hello|END|)");
		std::wstring replaced = LR"(hello　
 さよなら バカ こんにちは)";
		ProcessSentence(replaced, { nullptr });
		assert(replaced.rfind(L"さよなら") == std::wstring::npos);
		assert(replaced.rfind(L"バカ") == std::wstring::npos);
		assert(replaced.rfind(L"こんにちは") == std::wstring::npos);
		replacementTrie = {};
	}
);

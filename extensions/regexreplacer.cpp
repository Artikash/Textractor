#include "extension.h"
#include "module.h"
#include "blockmarkup.h"
#include <fstream>

extern const wchar_t* REGEX_REPLACER_INSTRUCTIONS;

const char* REGEX_REPLACEMENTS_SAVE_FILE = "SavedRegexReplacements.txt";

std::optional<std::wregex> regex;
concurrency::reader_writer_lock m;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		if (!std::ifstream(REGEX_REPLACEMENTS_SAVE_FILE).good())
		{
			auto file = std::ofstream(REGEX_REPLACEMENTS_SAVE_FILE, std::ios::binary) << "\xff\xfe";
			for (auto ch : std::wstring_view(REGEX_REPLACER_INSTRUCTIONS))
				file << (ch == L'\n' ? std::string_view("\r\0\n", 4) : std::string_view((char*)&ch, 2));
			_spawnlp(_P_DETACH, "notepad", "notepad", REGEX_REPLACEMENTS_SAVE_FILE, NULL); // show file to user
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

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (!sentenceInfo["current select"] || sentenceInfo["text number"] == 0) return false;
	std::regex::flag_type mod;
	std::regex_constants::match_flag_type flag;

	std::ifstream stream(REGEX_REPLACEMENTS_SAVE_FILE, std::ios::binary);
	BlockMarkupIterator savedFilters(stream, Array<std::wstring_view>{ L"|REGEX|", L"|BECOMES|", L"|MODIFIER|" });
	concurrency::reader_writer_lock::scoped_lock_read readLock(m);
	while (auto read = savedFilters.Next()) {		
		const auto& [regex, replacement, modifier] = read.value();
		if (modifier == L"g")
		{
			mod = std::regex::ECMAScript;
			flag = std::regex_constants::format_default;
		}
		else if (modifier == L"gi" || modifier == L"ig")
		{
			mod = std::regex::icase;
			flag = std::regex_constants::format_default;
		}
		else if (modifier == L"i")
		{
			mod = std::regex::icase;
			flag = std::regex_constants::format_first_only;
		}
		else
		{
			mod = std::regex::ECMAScript;
			flag = std::regex_constants::format_first_only;
		}
		try { ::regex =  std::wregex(regex, mod); }
		catch (std::regex_error) { continue; }

		sentence = std::regex_replace(sentence, ::regex.value(), replacement, flag);
	}
	return true;
}

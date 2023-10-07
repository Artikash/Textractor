#include "extension.h"
#include "blockmarkup.h"
#include <fstream>

extern const wchar_t* REGEX_REPLACER_INSTRUCTIONS;
extern const wchar_t* REPOSITORY;

constexpr auto REPLACE_SAVE_FILE = L"SavedRegexReplacements.txt";

std::wstring  replaceSaveFile;
std::wstring  currConfigFolder;

std::atomic<std::filesystem::file_time_type> replaceFileLastWrite = {};
concurrency::reader_writer_lock m;
std::vector<std::tuple<std::wregex, std::wstring, std::regex_constants::match_flag_type>> replacements;

void UpdateReplacements()
{
	try
	{
		if (replaceFileLastWrite.exchange(std::filesystem::last_write_time(replaceSaveFile)) == std::filesystem::last_write_time(replaceSaveFile)) return;
		std::scoped_lock lock(m);
		replacements.clear();
		std::ifstream stream(replaceSaveFile, std::ios::binary);
		BlockMarkupIterator savedFilters(stream, Array<std::wstring_view>{ L"|REGEX|", L"|BECOMES|", L"|MODIFIER|" });
		while (auto read = savedFilters.Next())
		{
			const auto& [regex, replacement, modifier] = read.value();
			try
			{
				replacements.emplace_back(
					std::wregex(regex, modifier.find(L'i') == std::string::npos ? std::regex::ECMAScript : std::regex::icase),
					replacement,
					modifier.find(L'g') == std::string::npos ? std::regex_constants::format_first_only : std::regex_constants::format_default
				);
			}
			catch (std::regex_error) {}
		}
	}
	catch (std::filesystem::filesystem_error) { replaceFileLastWrite.store({}); }
}

void InitializeReplacements()
{
	if (!std::filesystem::exists(replaceSaveFile))
	{
		auto file = std::ofstream(replaceSaveFile, std::ios::binary) << "\xff\xfe";
		for (auto ch : std::wstring_view(REGEX_REPLACER_INSTRUCTIONS))
			file << (ch == L'\n' ? std::string_view("\r\0\n", 4) : std::string_view((char*)&ch, 2));
		SpawnThread([] { _wspawnlp(_P_DETACH, L"notepad", L"notepad", replaceSaveFile.c_str(), NULL); }); // show file to user
	}
	replacements.clear();
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
	for (const auto& [regex, replacement, flags] : replacements) sentence = std::regex_replace(sentence, regex, replacement, flags);
	return true;
}
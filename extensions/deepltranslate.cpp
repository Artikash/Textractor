#include "qtcommon.h"
#include "extension.h"
#include "network.h"
#include <random>

extern const wchar_t* TRANSLATION_ERROR;
extern const char* USE_PREV_SENTENCE_CONTEXT;

extern Synchronized<std::wstring> translateTo, apiKey;

const char* TRANSLATION_PROVIDER = "DeepL Translate";
const char* GET_API_KEY_FROM = "https://www.deepl.com/pro.html";
QStringList languages
{
	"Chinese (simplified): ZH",
	"Dutch: NL",
	"English: EN",
	"French: FR",
	"German: DE",
	"Italian: IT",
	"Japanese: JA",
	"Polish: PL",
	"Portuguese: PT",
	"Russian: RU",
	"Spanish: ES",
};

bool translateSelectedOnly = true, rateLimitAll = true, rateLimitSelected = true, useCache = true;
int tokenCount = 10, tokenRestoreDelay = 60000, maxSentenceSize = 500;

const wchar_t* accept[] = { L"*/*", nullptr };
Synchronized<std::wstring> LMTBID;

std::pair<bool, std::wstring> Translate(const std::wstring& text)
{
	if (!apiKey->empty())
		if (HttpRequest httpRequest{
			L"Mozilla/5.0 Textractor",
			L"api.deepl.com",
			L"POST",
			L"/v2/translate",
			FormatString("text=%S&auth_key=%S&target_lang=%S", Escape(text), apiKey.Copy(), translateTo.Copy()),
			L"Content-Type: application/x-www-form-urlencoded"
		})
			// Response formatted as JSON: translation starts with text":" and ends with "}]
			if (std::wsmatch results; std::regex_search(httpRequest.response, results, std::wregex(L"text\":\"(.+?)\"\\}\\]"))) return { true, results[1] };
			else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
		else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };

	// the following code was reverse engineered from the DeepL website; it's as close as I could make it but I'm not sure what parts of this could be removed and still have it work
	int64_t r = _time64(nullptr), n = std::count(text.begin(), text.end(), L'i') + 1;
	int id = 10000 * std::uniform_int_distribution(0, 9999)(std::mt19937(std::random_device()()));
	// user_preferred_langs? what should priority be? does timestamp do anything? other translation quality options?
	auto body = FormatString(R"(
{
	"id": %d,
	"jsonrpc": "2.0",
	"method": "LMT_handle_jobs",
	"params": {
		"priority": -1,
		"timestamp": %lld,
		"lang": {
			"target_lang": "%S",
			"source_lang_user_selected": "auto"
		},
		"jobs": [{
			"raw_en_sentence": "%s",
			"raw_en_context_before": [],
			"kind": "default",
			"preferred_num_beams": 1,
			"quality": "fast",
			"raw_en_context_after": []
		}]
	}
}
	)", ++id, r + (n - r % n), translateTo.Copy(), JSON::Escape(text));
	// missing accept-encoding header since it fucks up HttpRequest
	std::wstring headers = L"Host: www2.deepl.com\r\nAccept-Language: en-US,en;q=0.5\r\nContent-type: text/plain; charset=utf-8\r\nOrigin: https://www.deepl.com\r\nTE: Trailers" + LMTBID.Acquire().contents;
	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"www2.deepl.com",
		L"POST",
		L"/jsonrpc",
		body,
		headers.c_str(),
		L"https://www.deepl.com/translator",
		WINHTTP_FLAG_SECURE,
		NULL,
		accept
	})
	{
		// Response formatted as JSON: translation starts with preprocessed_sentence":" and ends with ","
		if (std::wsmatch results; std::regex_search(httpRequest.response, results, std::wregex(L"postprocessed_sentence\":\"(.+?)\",\""))) return { true, results[1] };
		else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
	}
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

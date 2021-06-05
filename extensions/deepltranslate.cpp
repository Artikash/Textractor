#include "qtcommon.h"
#include "network.h"
#include <random>

extern const wchar_t* TRANSLATION_ERROR;

extern Synchronized<std::wstring> translateTo, translateFrom, authKey;

const char* TRANSLATION_PROVIDER = "DeepL Translate";
const char* GET_API_KEY_FROM = "https://www.deepl.com/pro.html";
QStringList languages
{
	"Bulgarian: BG",
	"Chinese: ZH",
	"Czech: CS",
	"Danish: DA",
	"Dutch: NL",
	"English: EN",
	"Estonian: ET",
	"Finnish: FI",
	"French: FR",
	"German: DE",
	"Greek: EL",
	"Hungarian: HU",
	"Italian: IT",
	"Japanese: JA",
	"Latvian: LV",
	"Lithuanian: LT",
	"Polish: PL",
	"Portuguese: PT",
	"Romanian: RO",
	"Russian: RU",
	"Slovak: SK",
	"Slovenian: SL",
	"Spanish: ES",
	"Swedish: SV"
};
std::wstring autoDetectLanguage = L"auto";

bool translateSelectedOnly = true, rateLimitAll = true, rateLimitSelected = true, useCache = true, useFilter = true;
int tokenCount = 10, tokenRestoreDelay = 60000, maxSentenceSize = 1000;

enum KeyType { CAT, REST };
int keyType = REST;
enum PlanLevel { FREE, PAID };
int planLevel = PAID;

std::pair<bool, std::wstring> Translate(const std::wstring& text)
{
	if (!authKey->empty())
	{
		std::string translateFromComponent = translateFrom.Copy() == autoDetectLanguage ? "" : "&source_lang=" + WideStringToString(translateFrom.Copy());
		if (HttpRequest httpRequest{
			L"Mozilla/5.0 Textractor",
			planLevel == PAID ? L"api.deepl.com" : L"api-free.deepl.com",
			L"POST",
			keyType == CAT ? L"/v1/translate" : L"/v2/translate",
			FormatString("text=%S&auth_key=%S&target_lang=%S", Escape(text), authKey.Copy(), translateTo.Copy()) + translateFromComponent,
			L"Content-Type: application/x-www-form-urlencoded"
		}; httpRequest && (!httpRequest.response.empty() || (httpRequest = HttpRequest{
			L"Mozilla/5.0 Textractor",
			planLevel == PAID ? L"api.deepl.com" : L"api-free.deepl.com",
			L"POST",
			(keyType = !keyType) == CAT ? L"/v1/translate" : L"/v2/translate",
			FormatString("text=%S&auth_key=%S&target_lang=%S", Escape(text), authKey.Copy(), translateTo.Copy()) + translateFromComponent,
			L"Content-Type: application/x-www-form-urlencoded"
		})) && (httpRequest.response.find(L"Wrong endpoint. Use") == std::string::npos || (httpRequest = HttpRequest{
			L"Mozilla/5.0 Textractor",
			(planLevel = !planLevel) == PAID ? L"api.deepl.com" : L"api-free.deepl.com",
			L"POST",
			keyType == CAT ? L"/v1/translate" : L"/v2/translate",
			FormatString("text=%S&auth_key=%S&target_lang=%S", Escape(text), authKey.Copy(), translateTo.Copy()) + translateFromComponent,
			L"Content-Type: application/x-www-form-urlencoded"
		})))
			// Response formatted as JSON: translation starts with text":" and ends with "}]
			if (auto translation = Copy(JSON::Parse(httpRequest.response)[L"translations"][0][L"text"].String())) return { true, translation.value() };
			else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
		else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
	}

	// the following code was reverse engineered from the DeepL website; it's as close as I could make it but I'm not sure what parts of this could be removed and still have it work
	int64_t r = _time64(nullptr), n = std::count(text.begin(), text.end(), L'i') + 1;
	thread_local auto generator = std::mt19937(std::random_device()());
	int id = 10000 * std::uniform_int_distribution(0, 9999)(generator) + 1;
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
			"source_lang_user_selected": "%S"
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
	)", id, r + (n - r % n), translateTo.Copy(), translateFrom.Copy(), JSON::Escape(WideStringToString(text)));
	// missing accept-encoding header since it fucks up HttpRequest
	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"www2.deepl.com",
		L"POST",
		L"/jsonrpc",
		body,
		L"Host: www2.deepl.com\r\nAccept-Language: en-US,en;q=0.5\r\nContent-type: application/json; charset=utf-8\r\nOrigin: https://www.deepl.com\r\nTE: Trailers",
		INTERNET_DEFAULT_PORT,
		L"https://www.deepl.com/translator",
		WINHTTP_FLAG_SECURE
	})
		if (auto translation = Copy(JSON::Parse(httpRequest.response)[L"result"][L"translations"][0][L"beams"][0][L"postprocessed_sentence"].String())) return { true, translation.value() };
		else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

#include "qtcommon.h"
#include "network.h"

extern const wchar_t* TRANSLATION_ERROR;

extern Synchronized<std::wstring> translateTo, translateFrom;

const char* TRANSLATION_PROVIDER = "Libre Translate";
const char* GET_API_KEY_FROM = nullptr;
QStringList languages
{
	"Arabic: ar",
	"Chinese: zh",
	"English: en",
	"French: fr",
	"German: de",
	"Hindi: hi",
	"Irish: ga",
	"Italian: it",
	"Japanese: ja",
	"Korean: ko",
	"Portuguese: pt",
	"Russian: ru",
	"Spanish: es"
};
std::wstring autoDetectLanguage = L"";

bool translateSelectedOnly = true, rateLimitAll = true, rateLimitSelected = false, useCache = true, useFilter = true;
int tokenCount = 10, tokenRestoreDelay = 60000, maxSentenceSize = 10000;

std::pair<bool, std::wstring> Translate(const std::wstring& text)
{
	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"127.0.0.1",
		L"POST",
		L"/translate",
		FormatString("q=%S&source=%S&target=%S", Escape(text), translateFrom.Copy(), translateTo.Copy()),
		NULL,
		5000,
		NULL,
		0
	})
		if (auto translation = Copy(JSON::Parse(httpRequest.response)[L"translatedText"].String())) return { true, translation.value() };
		else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

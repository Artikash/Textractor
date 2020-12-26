#include "extension.h"
#include "network.h"
#include <QStringList>

extern const wchar_t* TRANSLATION_ERROR;

extern Synchronized<std::wstring> translateTo, apiKey;

const char* TRANSLATION_PROVIDER = "Bing Translate";
const char* GET_API_KEY_FROM = "https://www.microsoft.com/en-us/translator/business/trial/#get-started";
QStringList languages
{
	"Afrikaans: af",
	"Arabic: ar",
	"Bangla: bn",
	"Bosnian: bs",
	"Bulgarian: bg",
	"Cantonese (traditional): yue",
	"Catalan: ca",
	"Chinese (simplified): zh-Hans",
	"Chinese (traditional): zh-Hant",
	"Croatian: hr",
	"Czech: cs",
	"Danish: da",
	"Dutch: nl",
	"English: en",
	"Estonian: et",
	"Fijian: fj",
	"Filipino: fil",
	"Finnish: fi",
	"French: fr",
	"German: de",
	"Greek: el",
	"Haitian Creole: ht",
	"Hebrew: he",
	"Hindi: hi",
	"Hmong Daw: mww",
	"Hungarian: hu",
	"Icelandic: is",
	"Indonesian: id",
	"Irish: ga",
	"Italian: it",
	"Japanese: ja",
	"Kannada: kn",
	"Klingon: tlh",
	"Korean: ko",
	"Latvian: lv",
	"Lithuanian: lt",
	"Malagasy: mg",
	"Malay: ms",
	"Malayalam: ml",
	"Maltese: mt",
	"Maori: mi",
	"Norwegian: nb",
	"Persian: fa",
	"Polish: pl",
	"Portuguese (Brazil): pt",
	"Portuguese (Portugal): pt-pt",
	"Punjabi: pa",
	"Romanian: ro",
	"Russian: ru",
	"Samoan: sm",
	"Serbian (Cyrillic): sr-Cyrl",
	"Serbian (Latin): sr-Latn",
	"Slovak: sk",
	"Slovenian: sl",
	"Spanish: es",
	"Swahili: sw",
	"Swedish: sv",
	"Tahitian: ty",
	"Tamil: ta",
	"Telugu: te",
	"Thai: th",
	"Tongan: to",
	"Turkish: tr",
	"Ukrainian: uk",
	"Urdu: ur",
	"Vietnamese: vi",
	"Welsh: cy",
	"Yucatec Maya: yua"
};

bool translateSelectedOnly = false, rateLimitAll = true, rateLimitSelected = false, useCache = true;
int tokenCount = 30, tokenRestoreDelay = 60000, maxSentenceSize = 500;

std::pair<bool, std::wstring> Translate(const std::wstring& text)
{
	if (!apiKey->empty())
		if (HttpRequest httpRequest{
			L"Mozilla/5.0 Textractor",
			L"api.cognitive.microsofttranslator.com",
			L"POST",
			FormatString(L"/translate?api-version=3.0&to=%s", translateTo.Copy()).c_str(),
			FormatString(R"([{"text":"%s"}])", JSON::Escape(WideStringToString(text))),
			FormatString(L"Content-Type: application/json; charset=UTF-8\r\nOcp-Apim-Subscription-Key:%s", apiKey.Copy()).c_str()
		})
		{
			if (auto translation = Copy(JSON::Parse(httpRequest.response)[0][L"translations"][0][L"text"].String())) return { true, translation.value() };
			else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
		}
		else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };

	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"www.bing.com",
		L"POST",
		FormatString(L"/ttranslatev3?fromLang=auto-detect&to=%s&text=%s", translateTo.Copy(), Escape(text)).c_str()
	})
		if (auto translation = Copy(JSON::Parse(httpRequest.response)[0][L"translations"][0][L"text"].String())) return { true, translation.value() };
		else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

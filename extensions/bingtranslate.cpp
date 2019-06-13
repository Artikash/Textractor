#include "extension.h"
#include "network.h"
#include <QStringList>

extern const wchar_t* TRANSLATION_ERROR;

const char* TRANSLATION_PROVIDER = "Bing";
QStringList languages
{
	"English: en",
	"Arabic: ar",
	"Bosnian: bs-Latn",
	"Bulgarian: bg",
	"Catalan: ca",
	"Chinese(Simplified): zh-CHS",
	"Chinese(Traditional): zh-CHT",
	"Croatian: hr",
	"Czech: cs",
	"Danish: da",
	"Dutch: nl",
	"Estonian: et",
	"Finnish: fi",
	"French: fr",
	"German: de",
	"Greek: el",
	"Hebrew: he",
	"Hindi: hi",
	"Hungarian: hu",
	"Indonesian: id",
	"Italian: it",
	"Japanese: ja",
	"Klingon: tlh",
	"Korean: ko",
	"Latvian: lv",
	"Lithuanian: lt",
	"Malay: ms",
	"Maltese: mt",
	"Norwegian: no",
	"Persian: fa",
	"Polish: pl",
	"Portuguese: pt",
	"Romanian: ro",
	"Russian: ru",
	"Serbian: sr-Cyrl",
	"Slovak: sk",
	"Slovenian: sl",
	"Spanish: es",
	"Swedish: sv",
	"Thai: th",
	"Turkish: tr",
	"Ukranian: uk",
	"Urdu: ur",
	"Vietnamese: vi",
	"Welsh: cy"
};
Synchronized<std::wstring> translateTo = L"en";

std::pair<bool, std::wstring> Translate(const std::wstring& text)
{
	std::wstring translateFrom;
	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"www.bing.com",
		L"POST",
		FormatString(L"/tdetect?text=%s", Escape(text)).c_str(),
		WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE,
	}) translateFrom = httpRequest.response;
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };

	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"www.bing.com",
		L"POST",
		FormatString(L"/ttranslate?from=%s&to=%s&text=%s", translateFrom, translateTo->c_str(), Escape(text)).c_str(),
		WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE,
	})
		// Response formatted as JSON: translation starts with :" and ends with "}
		if (std::wsmatch results; std::regex_search(httpRequest.response, results, std::wregex(L":\"(.+)\"\\}"))) return { true, results[1] };
		else return { false, TRANSLATION_ERROR };
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

#include "extension.h"
#include "network.h"
#include <QStringList>

extern const wchar_t* TRANSLATION_ERROR;

extern Synchronized<std::wstring> translateTo;

const char* TRANSLATION_PROVIDER = "Bing Translate";
QStringList languages
{
	"Afrikaans: af",
	"Arabic: ar",
	"Bangla: bn",
	"Bosnian: bs",
	"Bulgarian: bg",
	"Cantonese (Traditional): yue",
	"Catalan: ca",
	"Chinese (Simplified): zh-Hans",
	"Chinese (Traditional): zh-Hant",
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

std::pair<bool, std::wstring> Translate(const std::wstring& text, SentenceInfo)
{
	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"www.bing.com",
		L"POST",
		FormatString(L"/ttranslatev3?fromLang=auto-detect&to=%s&text=%s", translateTo->c_str(), Escape(text)).c_str()
	})
		// Response formatted as JSON: translation starts with text":" and ends with ","to
		if (std::wsmatch results; std::regex_search(httpRequest.response, results, std::wregex(L"text\":\"(.+?)\",\""))) return { true, results[1] };
		else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

#include "extension.h"
#include "network.h"
#include "util.h"
#include <ctime>
#include <QStringList>

extern const wchar_t* TRANSLATION_ERROR;

extern Synchronized<std::wstring> translateTo;

const char* TRANSLATION_PROVIDER = "Google";
QStringList languages
{
	"English: en",
	"Afrikaans: af",
	"Arabic: ar",
	"Albanian: sq",
	"Belarusian: be",
	"Bengali: bn",
	"Bosnian: bs",
	"Bulgarian: bg",
	"Catalan: ca",
	"Chinese(Simplified): zh-CH",
	"Chinese(Traditional): zh-TW",
	"Croatian: hr",
	"Czech: cs",
	"Danish: da",
	"Dutch: nl",
	"Esperanto: eo",
	"Estonian: et",
	"Filipino: tl",
	"Finnish: fi",
	"French: fr",
	"Galician: gl",
	"German: de",
	"Greek: el",
	"Hebrew: iw",
	"Hindi: hi",
	"Hungarian: hu",
	"Icelandic: is",
	"Indonesian: id",
	"Irish: ga",
	"Italian: it",
	"Japanese: ja",
	"Klingon: tlh",
	"Korean: ko",
	"Latin: la",
	"Latvian: lv",
	"Lithuanian: lt",
	"Macedonian: mk",
	"Malay: ms",
	"Maltese: mt",
	"Norwegian: no",
	"Persian: fa",
	"Polish: pl",
	"Portuguese: pt",
	"Romanian: ro",
	"Russian: ru",
	"Serbian: sr",
	"Slovak: sk",
	"Slovenian: sl",
	"Somali: so",
	"Spanish: es",
	"Swahili: sw",
	"Swedish: sv",
	"Thai: th",
	"Turkish: tr",
	"Ukranian: uk",
	"Urdu: ur",
	"Vietnamese: vi",
	"Welsh: cy",
	"Yiddish: yi",
	"Zulu: zu"
};

unsigned TKK = 0;

std::wstring GetTranslationUri(const std::wstring& text)
{
	// If no TKK available, use this uri. Can't use too much or google will detect unauthorized access
	if (!TKK) return FormatString(L"/translate_a/single?client=gtx&dt=ld&dt=rm&dt=t&tl=%s&q=%s", translateTo->c_str(), text);

	// Artikash 8/19/2018: reverse engineered from translate.google.com
	std::wstring escapedText;
	unsigned a = time(NULL) / 3600, b = a; // the first part of TKK
	for (unsigned char ch : WideStringToString(text))
	{
		escapedText += FormatString(L"%%%02X", (int)ch);
		a += ch;
		a += a << 10;
		a ^= a >> 6;
	}
	a += a << 3;
	a ^= a >> 11;
	a += a << 15;
	a ^= TKK;
	a %= 1000000;

	return FormatString(L"/translate_a/single?client=webapp&dt=ld&dt=rm&dt=t&sl=auto&tl=%s&tk=%u.%u&q=%s", translateTo->c_str(), a, a ^ b, escapedText);
}

bool IsHash(const std::wstring& result)
{
	return result.size() == 32 && std::all_of(result.begin(), result.end(), [](auto ch) { return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'z'); });
}

std::pair<bool, std::wstring> Translate(const std::wstring& text)
{
	if (!TKK)
		if (HttpRequest httpRequest{ L"Mozilla/5.0 Textractor", L"translate.google.com", L"GET", L"/" })
			if (std::wsmatch results; std::regex_search(httpRequest.response, results, std::wregex(L"(\\d{7,})'")))
				_InterlockedCompareExchange(&TKK, stoll(results[1]), 0);

	if (HttpRequest httpRequest{ L"Mozilla/5.0 Textractor", L"translate.googleapis.com", L"GET", GetTranslationUri(text).c_str() })
	{
		// Response formatted as JSON: starts with "[[[" and translation is enclosed in quotes followed by a comma
		if (httpRequest.response[0] == L'[')
		{
			std::wstring translation;
			for (std::wsmatch results; std::regex_search(httpRequest.response, results, std::wregex(L"\\[\"(.*?)\",[n\"]")); httpRequest.response = results.suffix())
				if (!IsHash(results[1])) translation += std::wstring(results[1]) + L" ";
			if (!translation.empty()) return { true, translation };
		}
		return { false, FormatString(L"%s (TKK=%u)", TRANSLATION_ERROR, _InterlockedExchange(&TKK, 0)) };
	}
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

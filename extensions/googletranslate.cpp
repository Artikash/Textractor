#include "qtcommon.h"
#include "extension.h"
#include "network.h"
#include <ctime>

extern const wchar_t* TRANSLATION_ERROR;
extern const char* API_KEY;

extern QFormLayout* display;
extern QSettings settings;
extern Synchronized<std::wstring> translateTo;

const char* TRANSLATION_PROVIDER = "Google Translate";
QStringList languages
{
	"Afrikaans: af",
	"Arabic: ar",
	"Albanian: sq",
	"Belarusian: be",
	"Bengali: bn",
	"Bosnian: bs",
	"Bulgarian: bg",
	"Catalan: ca",
	"Chinese (simplified): zh-CH",
	"Chinese (traditional): zh-TW",
	"Croatian: hr",
	"Czech: cs",
	"Danish: da",
	"Dutch: nl",
	"English: en",
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

bool translateSelectedOnly = false, rateLimitAll = true, rateLimitSelected = false, useCache = true;
int tokenCount = 30, tokenRestoreDelay = 60000;

Synchronized<std::wstring> key;

unsigned TKK = 0;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		auto keyInput = new QLineEdit(settings.value(API_KEY).toString());
		key->assign(S(keyInput->text()));
		QObject::connect(keyInput, &QLineEdit::textChanged, [](QString key) { settings.setValue(API_KEY, S(::key->assign(S(key)))); });
		display->addRow(API_KEY, keyInput);
		auto googleCloudInfo = new QLabel(
			"<a href=\"https://codelabs.developers.google.com/codelabs/cloud-translation-intro\">https://codelabs.developers.google.com/codelabs/cloud-translation-intro</a>"
		);
		googleCloudInfo->setOpenExternalLinks(true);
		display->addRow(googleCloudInfo);
	}
	break;
	case DLL_PROCESS_DETACH:
	{
	}
	break;
	}
	return TRUE;
}

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
	return result.size() == 32 && std::all_of(result.begin(), result.end(), [](char ch) { return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'z'); });
}

std::pair<bool, std::wstring> Translate(const std::wstring& text, SentenceInfo)
{
	if (!key->empty())
	{
		if (HttpRequest httpRequest{
			L"Mozilla/5.0 Textractor",
			L"translation.googleapis.com",
			L"GET",
			FormatString(L"/language/translate/v2?format=text&q=%s&target=%s&key=%s", Escape(text), translateTo->c_str(), key->c_str()).c_str()
		})
		{
			// Response formatted as JSON: starts with "translatedText": " and translation is enclosed in quotes followed by a comma
			if (std::wsmatch results; std::regex_search(httpRequest.response, results, std::wregex(L"\"translatedText\": \"(.+?)\","))) return { true, results[1] };
			return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
		}
		else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
	}

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
		return { false, FormatString(L"%s (TKK=%u): %s", TRANSLATION_ERROR, _InterlockedExchange(&TKK, 0), httpRequest.response) };
	}
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

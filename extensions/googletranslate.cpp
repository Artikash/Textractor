#include "qtcommon.h"
#include "network.h"
#include <ctime>

extern const wchar_t* TRANSLATION_ERROR;

extern Synchronized<std::wstring> translateTo, translateFrom, authKey;

const char* TRANSLATION_PROVIDER = "Google Translate";
const char* GET_API_KEY_FROM = "https://codelabs.developers.google.com/codelabs/cloud-translation-intro";
QStringList languages
{
	"Afrikaans: af",
	"Albanian: sq",
	"Amharic: am",
	"Arabic: ar",
	"Armenian: hy",
	"Azerbaijani: az",
	"Basque: eu",
	"Belarusian: be",
	"Bengali: bn",
	"Bosnian: bs",
	"Bulgarian: bg",
	"Catalan: ca",
	"Cebuano: ceb",
	"Chichewa: ny",
	"Chinese (simplified): zh",
	"Chinese (traditional): zh-TW",
	"Corsican: co",
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
	"Frisian: fy",
	"Galician: gl",
	"Georgian: ka",
	"German: de",
	"Greek: el",
	"Gujarati: gu",
	"Haitian Creole: ht",
	"Hausa: ha",
	"Hawaiian: haw",
	"Hebrew: iw",
	"Hindi: hi",
	"Hmong: hmn",
	"Hungarian: hu",
	"Icelandic: is",
	"Igbo: ig",
	"Indonesian: id",
	"Irish: ga",
	"Italian: it",
	"Japanese: ja",
	"Javanese: jw",
	"Kannada: kn",
	"Kazakh: kk",
	"Khmer: km",
	"Kinyarwanda: rw",
	"Korean: ko",
	"Kurdish (Kurmanji): ku",
	"Kyrgyz: ky",
	"Lao: lo",
	"Latin: la",
	"Latvian: lv",
	"Lithuanian: lt",
	"Luxembourgish: lb",
	"Macedonian: mk",
	"Malagasy: mg",
	"Malay: ms",
	"Malayalam: ml",
	"Maltese: mt",
	"Maori: mi",
	"Marathi: mr",
	"Mongolian: mn",
	"Myanmar (Burmese): my",
	"Nepali: ne",
	"Norwegian: no",
	"Odia (Oriya): or",
	"Pashto: ps",
	"Persian: fa",
	"Polish: pl",
	"Portuguese: pt",
	"Punjabi: pa",
	"Romanian: ro",
	"Russian: ru",
	"Samoan: sm",
	"Scots Gaelic: gd",
	"Serbian: sr",
	"Sesotho: st",
	"Shona: sn",
	"Sindhi: sd",
	"Sinhala: si",
	"Slovak: sk",
	"Slovenian: sl",
	"Somali: so",
	"Spanish: es",
	"Sundanese: su",
	"Swahili: sw",
	"Swedish: sv",
	"Tajik: tg",
	"Tamil: ta",
	"Tatar: tt",
	"Telugu: te",
	"Thai: th",
	"Turkish: tr",
	"Turkmen: tk",
	"Ukrainian: uk",
	"Urdu: ur",
	"Uyghur: ug",
	"Uzbek: uz",
	"Vietnamese: vi",
	"Welsh: cy",
	"Xhosa: xh",
	"Yiddish: yi",
	"Yoruba: yo",
	"Zulu: zu"
};
std::wstring autoDetectLanguage = L"auto";

bool translateSelectedOnly = false, rateLimitAll = true, rateLimitSelected = false, useCache = true, useFilter = true;
int tokenCount = 30, tokenRestoreDelay = 60000, maxSentenceSize = 1000;

std::pair<bool, std::wstring> Translate(const std::wstring& text)
{
	if (!authKey->empty())
	{
		std::wstring translateFromComponent = translateFrom.Copy() == autoDetectLanguage ? L"" : L"&source=" + translateFrom.Copy();
		if (HttpRequest httpRequest{
			L"Mozilla/5.0 Textractor",
			L"translation.googleapis.com",
			L"POST",
			FormatString(L"/language/translate/v2?format=text&target=%s&key=%s%s", translateTo.Copy(), authKey.Copy(), translateFromComponent).c_str(),
			FormatString(R"({"q":["%s"]})", JSON::Escape(WideStringToString(text)))
		})
			if (auto translation = Copy(JSON::Parse(httpRequest.response)[L"data"][L"translations"][0][L"translatedText"].String())) return { true, translation.value() };
			else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
		else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
	}

	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"translate.google.com",
		L"GET",
		FormatString(L"/m?sl=%s&tl=%s&q=%s", translateFrom.Copy(), translateTo.Copy(), Escape(text)).c_str()
	})
	{
		auto start = httpRequest.response.find(L"result-container\">"), end = httpRequest.response.find(L'<', start);
		if (end != std::string::npos) return { true, HTML::Unescape(httpRequest.response.substr(start + 18, end - start - 18)) };
		return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
	}
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

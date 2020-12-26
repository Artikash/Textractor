#include "qtcommon.h"
#include "extension.h"
#include "network.h"
#include <ctime>

extern const wchar_t* TRANSLATION_ERROR;

extern Synchronized<std::wstring> translateTo, apiKey;

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

bool translateSelectedOnly = false, rateLimitAll = true, rateLimitSelected = false, useCache = true;
int tokenCount = 30, tokenRestoreDelay = 60000, maxSentenceSize = 500;

std::pair<bool, std::wstring> Translate(const std::wstring& text)
{
	if (!apiKey->empty())
		if (HttpRequest httpRequest{
			L"Mozilla/5.0 Textractor",
			L"translation.googleapis.com",
			L"POST",
			FormatString(L"/language/translate/v2?format=text&target=%s&key=%s", translateTo.Copy(), apiKey.Copy()).c_str(),
			FormatString(R"({"q":["%s"]})", JSON::Escape(WideStringToString(text)))
		})
			if (auto translation = Copy(JSON::Parse(httpRequest.response)[L"data"][L"translations"][0][L"translatedText"].String())) return { true, translation.value() };
			else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
		else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };

	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"translate.google.com",
		L"POST",
		L"/_/TranslateWebserverUi/data/batchexecute?rpcids=MkEWBc",
		"f.req=" + Escape(WideStringToString(FormatString(LR"([[["MkEWBc","[[\"%s\",\"auto\",\"%s\",true],[null]]",null,"generic"]]])", JSON::Escape((JSON::Escape(text))), translateTo.Copy()))),
		L"Content-Type: application/x-www-form-urlencoded"
	})
	{
		if (auto start = httpRequest.response.find(L"[["); start != std::string::npos)
		{
			if (auto blob = Copy(JSON::Parse(httpRequest.response.substr(start))[0][2].String())) if (auto translations = Copy(JSON::Parse(blob.value())[1][0].Array()))
			{
				std::wstring translation;
				if (translations->size() == 1 && (translations = Copy(translations.value()[0][5].Array())))
				{
					for (const auto& sentence : translations.value()) if (sentence[0].String()) (translation += *sentence[0].String()) += L" ";
				}
				else
				{
					for (const auto& conjugation : translations.value())
						if (auto sentence = conjugation[0].String()) if (auto gender = conjugation[2].String()) translation += FormatString(L"%s %s\n", *sentence, *gender);
				}
				if (!translation.empty()) return { true, translation };
				return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, blob.value()) };
			}
		}
		return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
	}
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

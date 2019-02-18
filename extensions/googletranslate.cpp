#include "extension.h"
#include "defs.h"
#include "text.h"
#include "util.h"
#include "network.h"
#include <ctime>
#include <QInputDialog>
#include <QTimer>

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

std::wstring translateTo = L"en";

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		QTimer::singleShot(0, []
		{
			translateTo = QInputDialog::getItem(
				nullptr, 
				SELECT_LANGUAGE, 
				GOOGLE_PROMPT, 
				languages, 
				0, false, nullptr,
				Qt::WindowCloseButtonHint
			).split(" ")[1].toStdWString();
		});
	}
	break;
	case DLL_PROCESS_DETACH:
	{
	}
	break;
	}
	return TRUE;
}

std::wstring GetTranslationUri(const std::wstring& text, unsigned TKK)
{
	// If no TKK available, use this uri. Can't use too much or google will detect unauthorized access
	if (!TKK) return L"/translate_a/single?client=gtx&dt=ld&dt=rm&dt=t&tl=" + translateTo + L"&q=" + text;

	// Artikash 8/19/2018: reverse engineered from translate.google.com
	std::wstring escapedText;
	unsigned a = _time64(NULL) / 3600, b = a; // <- the first part of TKK
	for (unsigned char ch : WideStringToString(text))
	{
		wchar_t escapedChar[4] = {};
		swprintf_s<4>(escapedChar, L"%%%02X", (int)ch);
		escapedText += escapedChar;
		a += ch;
		a += a << 10;
		a ^= a >> 6;
	}
	a += a << 3;
	a ^= a >> 11;
	a += a << 15;
	a ^= TKK;
	a %= 1000000;
	b ^= a;

	return L"/translate_a/single?client=t&dt=ld&dt=rm&dt=t&tl=" + translateTo + L"&tk=" + std::to_wstring(a) + L"." + std::to_wstring(b) + L"&q=" + escapedText;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0) return false;

	static std::atomic<HINTERNET> internet = NULL;
	if (!internet) internet = WinHttpOpen(L"Mozilla/5.0 Textractor", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
	static std::atomic<unsigned> TKK = 0;
	static RateLimiter rateLimiter(30, 60 * 1000);

	std::wstring translation;
	if (!(rateLimiter.Request() || sentenceInfo["current select"])) translation = TOO_MANY_TRANS_REQUESTS;
	else if (internet)
	{
		if (!TKK)
			if (InternetHandle connection = WinHttpConnect(internet, L"translate.google.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
				if (InternetHandle request = WinHttpOpenRequest(connection, L"GET", L"/", NULL, NULL, NULL, WINHTTP_FLAG_SECURE))
					if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
						if (auto response = ReceiveHttpRequest(request))
							if (std::wsmatch results; std::regex_search(response.value(), results, std::wregex(L"(\\d{7,})'"))) TKK = stoll(results[1]);

		if (InternetHandle connection = WinHttpConnect(internet, L"translate.google.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
			if (InternetHandle request = WinHttpOpenRequest(connection, L"GET", GetTranslationUri(sentence, TKK).c_str(), NULL, NULL, NULL, WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE))
				if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
					if (auto response = ReceiveHttpRequest(request))
						// Response formatted as JSON: starts with [[["
						if (response.value()[0] == L'[')
						{
							for (std::wsmatch results; std::regex_search(response.value(), results, std::wregex(L"\\[\"(.*?)\",[n\"]")); response = results.suffix())
								translation += std::wstring(results[1]) + L" ";
							Escape(translation);
						}
						else
						{
							translation = TRANSLATION_ERROR + (L" (TKK=" + std::to_wstring(TKK) + L")");
							TKK = 0;
						}
	}

	if (translation.empty()) translation = TRANSLATION_ERROR;
	sentence += L"\n" + translation;
	return true;
}

TEST(
	{
		std::wstring test = L"こんにちは";
		ProcessSentence(test, { SentenceInfo::DUMMY });
		assert(test.find(L"Hello") != std::wstring::npos);
	}
);

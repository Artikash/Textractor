#include "extension.h"
#include "defs.h"
#include "text.h"
#include "network.h"
#include <QInputDialog>
#include <QTimer>

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
				BING_PROMPT,
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

// This function detects language and returns it if translateFrom is empty
std::wstring Translate(const std::wstring& text, std::wstring translateFrom, std::wstring translateTo)
{
	static std::atomic<HINTERNET> internet = NULL;
	if (!internet) internet = WinHttpOpen(L"Mozilla/5.0 Textractor", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);

	std::wstring escapedText;
	for (unsigned char ch : WideStringToString(text))
	{
		wchar_t escapedChar[4] = {};
		swprintf_s<4>(escapedChar, L"%%%02X", (int)ch);
		escapedText += escapedChar;
	}

	std::wstring location = translateFrom.empty()
		? L"/tdetect?text=" + escapedText
		: L"/ttranslate?from=" + translateFrom + L"&to=" + translateTo + L"&text=" + escapedText;
	std::wstring translation;
	if (internet)
		if (InternetHandle connection = WinHttpConnect(internet, L"www.bing.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
			if (InternetHandle request = WinHttpOpenRequest(connection, L"POST", location.c_str(), NULL, NULL, NULL, WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE))
				if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
					if (auto response = ReceiveHttpRequest(request))
						if (translateFrom.empty()) translation = response.value();
						// Response formatted as JSON: translation starts with :" and ends with "}
						else if (std::wsmatch results; std::regex_search(response.value(), results, std::wregex(L":\"(.+)\"\\}"))) translation = results[1];

	Escape(translation);
	return translation;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0) return false;

	static RateLimiter rateLimiter(30, 60 * 1000);

	std::wstring translation;
	if (!(rateLimiter.Request() || sentenceInfo["current select"])) translation = TOO_MANY_TRANS_REQUESTS;
	else translation = Translate(sentence, Translate(sentence, L"", translateTo), translateTo);
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

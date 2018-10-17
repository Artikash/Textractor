#include "extension.h"
#include <winhttp.h>
#include <regex>
#include <QInputDialog>
#include <QSettings>

QStringList languages
{
	"English: en",
	"Japanese: ja",
	"Hebrew: he",
	"Arabic: ar",
	"Hindi: hi",
	"Romanian: ro",
	"Bosnian: bs-Latn",
	"Russian: ru",
	"Bulgarian: bg",
	"Hungarian: hu",
	"Serbian: sr-Cyrl",
	"Catalan: ca",
	"Indonesian: id",
	"Chinese(Simplified): zh-CHS",
	"Italian: it",
	"Slovak: sk",
	"Chinese(Traditional): zh-CHT",
	"Slovenian: sl",
	"Croatian: hr",
	"Klingon: tlh", // Wait what? Apparently Bing supports this???????
	"Spanish: es",
	"Czech: cs",
	"Swedish: sv",
	"Danish: da",
	"Korean: ko",
	"Thai: th",
	"Dutch: nl",
	"Latvian: lv",
	"Turkish: tr",
	"Lithuanian: lt",
	"Ukranian: uk",
	"Estonian: et",
	"Malay: ms",
	"Urdu: ur",
	"Finnish: fi",
	"Maltese: mt",
	"Vietnamese: vi",
	"French: fr",
	"Norwegian: no",
	"Welsh: cy",
	"German: de",
	"Persian: fa",
	"Greek: el",
	"Polish: pl",
	"Portuguese: pt"
};
QString translateFrom;
QString translateTo;

QString GetLanguage(QString prompt)
{
	bool ok;
	QString ret = QInputDialog::getItem(nullptr, prompt, prompt, languages, 0, false, &ok);
	if (!ok) ret = "English: en";
	return ret.split(" ")[1];
}

std::wstring GetTranslationUri(std::wstring text)
{
	return ("/ttranslate?from=" + translateFrom + "&to=" + translateTo + "&text=").toStdWString() + text;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	static bool languagesLoaded = false;
	if (!languagesLoaded)
	{
		languages.sort();
		QSettings translateSettings("Bing Translation.ini", QSettings::IniFormat);
		if (translateSettings.contains("Translate_From")) translateFrom = translateSettings.value("Translate_From").toString();
		else translateSettings.setValue("Translate_From", translateFrom = GetLanguage("What language should Bing translate from?"));
		if (translateSettings.contains("Translate_To")) translateTo = translateSettings.value("Translate_To").toString();
		else translateSettings.setValue("Translate_To", translateTo = GetLanguage("What language should Bing translate to?"));
		translateSettings.sync();
		languagesLoaded = true;
	}

	static HINTERNET internet = NULL;
	if (!internet) internet = WinHttpOpen(L"Mozilla/5.0 Textractor", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);

	std::wstring translation;

	if (sentenceInfo["hook address"] == -1 || sentenceInfo["current select"] != 1) return false;

	if (internet)
	{
		if (HINTERNET connection = WinHttpConnect(internet, L"www.bing.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
		{
			if (HINTERNET request = WinHttpOpenRequest(connection, L"POST", (GetTranslationUri(sentence)).c_str(), NULL, NULL, NULL, WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE))
			{
				if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
				{
					DWORD bytesRead;
					char buffer[10000] = {};
					WinHttpReceiveResponse(request, NULL);
					WinHttpReadData(request, buffer, 10000, &bytesRead);
					// Response formatted as JSON: starts with '{'
					if (buffer[0] == '{')
					{
						wchar_t wbuffer[10000] = {};
						MultiByteToWideChar(CP_UTF8, 0, buffer, -1, wbuffer, 10000);
						if (std::wcmatch results; std::regex_search(wbuffer, results, std::wregex(L":\"(.+)\"\\}"))) translation = results[1];
						for (auto& c : translation) if (c == L'\\') c = 0x200b;
					}
				}
				WinHttpCloseHandle(request);
			}
			WinHttpCloseHandle(connection);
		}
	}

	if (translation == L"") translation = L"Error while translating.";
	sentence += L"\r\n" + translation;
	return true;
}
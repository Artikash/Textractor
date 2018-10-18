#include "extension.h"
#include <winhttp.h>
#include <regex>
#include <QInputDialog>
#include <QApplication>
#include <QThread>

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

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	static HINTERNET internet = NULL;
	if (!internet) internet = WinHttpOpen(L"Mozilla/5.0 Textractor", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);

	static std::wstring translateTo;
	if (translateTo == L"" && QApplication::instance()->thread() == QThread::currentThread())
	{
		languages.sort();
		bool ok;
		QString language = QInputDialog::getItem(nullptr, "Select Language", "What language should Bing translate to?", languages, 0, false, &ok);
		if (!ok) language = "English: en";
		translateTo = language.split(" ")[1].toStdWString();
	}

	if (sentenceInfo["hook address"] == -1 || sentenceInfo["current select"] != 1) return false;

	std::wstring translation;
	std::wstring translateFrom;

	if (internet)
	{
		if (HINTERNET connection = WinHttpConnect(internet, L"www.bing.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
		{
			if (HINTERNET request = WinHttpOpenRequest(
				connection, L"POST", 
				(L"/tdetect?text=" + sentence).c_str(),
				NULL, NULL, NULL,
				WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE
			))
			{
				if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
				{
					DWORD bytesRead;
					char buffer[10000] = {};
					WinHttpReceiveResponse(request, NULL);
					WinHttpReadData(request, buffer, 10000, &bytesRead);
					translateFrom = std::wstring(buffer, buffer + bytesRead);
				}
				WinHttpCloseHandle(request);
			}

			if (HINTERNET request = WinHttpOpenRequest(
				connection, 
				L"POST", 
				(L"/ttranslate?from=" + translateFrom + L"&to=" + translateTo + L"&text=" + sentence).c_str(), 
				NULL, NULL, NULL, 
				WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE
			))
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
#include "../extension.h"
#include <winhttp.h>
#include <vector>
#include <mutex>
#include <algorithm>
#include <regex>
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

std::wstring translateTo;

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
				"Select Language",
				"What language should Bing translate to?",
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

// This function detects language and puts it in translateFrom if it's empty
std::wstring Translate(std::wstring text, std::wstring& translateFrom, std::wstring translateTo)
{
	static HINTERNET internet = NULL;
	if (!internet) internet = WinHttpOpen(L"Mozilla/5.0 Textractor", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);

	char utf8[10000] = {};
	WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, utf8, 10000, NULL, NULL);
	text.clear();
	for (int i = 0; utf8[i];)
	{
		wchar_t utf8char[3] = {};
		swprintf_s<3>(utf8char, L"%02X", (int)(unsigned char)utf8[i++]);
		text += L"%" + std::wstring(utf8char);
	}

	std::wstring translation;
	if (internet)
	{
		std::wstring location = translateFrom.empty()
			? L"/tdetect?text=" + text
			: L"/ttranslate?from=" + translateFrom + L"&to=" + translateTo + L"&text=" + text;
		if (HINTERNET connection = WinHttpConnect(internet, L"www.bing.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
		{
			if (HINTERNET request = WinHttpOpenRequest(connection, L"POST", location.c_str(), NULL, NULL, NULL, WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE))
			{
				if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
				{
					DWORD bytesRead;
					char buffer[10000] = {};
					WinHttpReceiveResponse(request, NULL);
					WinHttpReadData(request, buffer, 10000, &bytesRead);
					wchar_t wbuffer[10000] = {};
					MultiByteToWideChar(CP_UTF8, 0, buffer, -1, wbuffer, 10000);
					if (translateFrom.empty()) translateFrom = wbuffer;
					// Response formatted as JSON: translation starts with :" and ends with "}
					if (std::wcmatch results; std::regex_search(wbuffer, results, std::wregex(L":\"(.+)\"\\}"))) translation = results[1];
				}
				WinHttpCloseHandle(request);
			}
			WinHttpCloseHandle(connection);
		}
	}
	return translation;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["hook address"] == -1) return false;

	{
		static std::mutex m;
		static std::vector<DWORD> requestTimes;
		std::lock_guard l(m);
		requestTimes.push_back(GetTickCount());
		requestTimes.erase(std::remove_if(requestTimes.begin(), requestTimes.end(), [&](DWORD requestTime) { return GetTickCount() - requestTime > 60 * 1000; }), requestTimes.end());
		if (!sentenceInfo["current select"] && requestTimes.size() > 30)
		{
			sentence += L"\r\nToo many translation requests: refuse to make more.";
			return true;
		}
	}

	std::wstring translation, translateFrom;
	Translate(sentence, translateFrom, translateTo);
	translation = Translate(sentence, translateFrom, translateTo);
	for (auto& c : translation) if (c == L'\\') c = 0x200b;
	if (translation.empty()) translation = L"Error while translating.";
	sentence += L"\r\n" + translation;
	return true;
}
#include "extension.h"
#include <winhttp.h>
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
				"What language should Google translate to?", 
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

std::wstring GetTranslationUri(std::wstring text, unsigned TKK)
{
	// If no TKK available, use this uri. Can't use too much or google will detect unauthorized access
	if (!TKK) return L"/translate_a/single?client=gtx&dt=ld&dt=rm&dt=t&tl=" + translateTo + L"&q=" + text;

	// Artikash 8/19/2018: reverse engineered from translate.google.com
	char utf8[10000] = {};
	WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, utf8, 10000, NULL, NULL);

	unsigned a = (unsigned)(_time64(NULL) / 3600), b = a; // <- the first part of TKK
	for (int i = 0; utf8[i];)
	{
		a += (unsigned char)utf8[i++];
		a += a << 10;
		a ^= a >> 6;
	}
	a += a << 3;
	a ^= a >> 11;
	a += a << 15;
	a ^= TKK;
	a %= 1000000;
	b ^= a;

	text.clear();
	for (int i = 0; utf8[i];)
	{
		wchar_t utf8char[3] = {};
		swprintf_s<3>(utf8char, L"%02X", (int)(unsigned char)utf8[i++]);
		text += L"%" + std::wstring(utf8char);
	}

	return L"/translate_a/single?client=t&dt=ld&dt=rm&dt=t&tl=" + translateTo + L"&tk=" + std::to_wstring(a) + L"." + std::to_wstring(b) + L"&q=" + text;
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
			sentence += L"\r\nToo many translation requests: refuse to make more";
			return true;
		}
	}

	static HINTERNET internet = NULL;
	if (!internet) internet = WinHttpOpen(L"Mozilla/5.0 Textractor", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
	static unsigned TKK = 0;
	std::wstring translation;
	if (internet)
	{
		if (HINTERNET connection = WinHttpConnect(internet, L"translate.google.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
		{
			if (HINTERNET request = WinHttpOpenRequest(connection, L"GET", L"/", NULL, NULL, NULL, WINHTTP_FLAG_SECURE))
			{
				if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
				{
					DWORD bytesRead;
					char buffer[200000] = {}; // Google Translate page is ~180kb (good god the bloat >_>)
					WinHttpReceiveResponse(request, NULL);
					WinHttpReadData(request, buffer, 200000, &bytesRead);
					if (std::cmatch results; std::regex_search(buffer, results, std::regex("(\\d{7,})'"))) TKK = stoll(results[1]);
				}
				WinHttpCloseHandle(request);
			}
			WinHttpCloseHandle(connection);
		}

		if (HINTERNET connection = WinHttpConnect(internet, L"translate.google.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
		{
			if (HINTERNET request = WinHttpOpenRequest(connection, L"GET", GetTranslationUri(sentence, TKK).c_str(), NULL, NULL, NULL, WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE))
			{
				if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
				{
					DWORD bytesRead;
					char buffer[10000] = {};
					WinHttpReceiveResponse(request, NULL);
					WinHttpReadData(request, buffer, 10000, &bytesRead);
					// Response formatted as JSON: starts with '[[["'
					if (buffer[0] == '[')
					{
						wchar_t wbuffer[10000] = {};
						MultiByteToWideChar(CP_UTF8, 0, buffer, -1, wbuffer, 10000);
						std::wstring response(wbuffer);
						for (std::wsmatch results; std::regex_search(response, results, std::wregex(L"\\[\"(.*?)\",[n\"]")); response = results.suffix())
							translation += std::wstring(results[1]) + L" ";
						for (auto& c : translation) if (c == L'\\') c = 0x200b;
					}
				}
				WinHttpCloseHandle(request);
			}
			WinHttpCloseHandle(connection);
		}
	}

	if (translation.empty()) translation = L"Error while translating (TKK=" + std::to_wstring(TKK) + L")";
	sentence += L"\r\n" + translation;
	return true;
}
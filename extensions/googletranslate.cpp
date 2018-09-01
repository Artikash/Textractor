#include "extensions.h"
#include <winhttp.h>
#include <ctime>
#include <regex>

std::wstring GetTranslationUri(const wchar_t* text, unsigned int TKK)
{
	// If no TKK available, use this uri. Can't use too much or google will detect unauthorized access.
	if (!TKK) return std::wstring(L"/translate_a/single?client=gtx&dt=ld&dt=rm&dt=tq=") + text;

	// Artikash 8/19/2018: reverse engineered from translate.google.com
	char* utf8text = new char[wcslen(text) * 4];
	WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8text, wcslen(text) * 4, NULL, NULL);

	unsigned int a = (unsigned int)(_time64(NULL) / 3600), b = a; // <- the first part of TKK
	for (int i = 0; utf8text[i];)
	{
		a += (unsigned char)utf8text[i++];
		a += a << 10;
		a ^= a >> 6;
	}
	a += a << 3;
	a ^= a >> 11;
	a += a << 15;
	a ^= TKK;
	a %= 1000000;
	b ^= a;

	delete[] utf8text;
	return std::wstring(L"/translate_a/single?client=t&dt=ld&dt=rm&dt=t&tk=") + std::to_wstring(a) + L"." + std::to_wstring(b) + L"&q=" + std::wstring(text);
}

bool ProcessSentence(std::wstring& sentence, const InfoForExtension* miscInfo)
{
	static HINTERNET internet = NULL;
	if (!internet) internet = WinHttpOpen(L"Mozilla/5.0 NextHooker", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
	static unsigned int TKK = 0;

	std::wstring translation(L"");

	if (GetProperty("hook address", miscInfo) == -1) return false;

	if (internet)
	{
		if (!TKK)
			if (HINTERNET connection = WinHttpConnect(internet, L"translate.google.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
			{
				if (HINTERNET request = WinHttpOpenRequest(connection, L"GET", L"/", NULL, NULL, NULL, WINHTTP_FLAG_SECURE))
				{
					if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
					{
						DWORD bytesRead;
						char buffer[100000] = {}; // Google Translate page is ~64kb
						WinHttpReceiveResponse(request, NULL);
						WinHttpReadData(request, buffer, 100000, &bytesRead);
						TKK = strtoll(strstr(buffer, "a\\x3d") + 5, nullptr, 10) + strtoll(strstr(buffer, "b\\x3d") + 5, nullptr, 10);
					}
					WinHttpCloseHandle(request);
				}
				WinHttpCloseHandle(connection);
			}

		if (HINTERNET connection = WinHttpConnect(internet, L"translate.google.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
		{
			if (HINTERNET request = WinHttpOpenRequest(connection, L"GET", GetTranslationUri(sentence.c_str(), TKK).c_str(), NULL, NULL, NULL, WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE))
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
						MultiByteToWideChar(CP_UTF8, 0, (char*)buffer, -1, wbuffer, 10000);
						std::wstring response(wbuffer);
						std::wregex translationFinder(L"\\[\"(.*?)\",[n\"]");
						std::wsmatch results;
						while (std::regex_search(response, results, translationFinder))
						{
							translation += std::wstring(results[1]) + L" ";
							response = results.suffix().str();
						}
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
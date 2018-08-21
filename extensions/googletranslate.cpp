#include "extensions.h"
#include <winhttp.h>
#include <ctime>

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

	return std::wstring(L"/translate_a/single?client=t&dt=ld&dt=rm&dt=t&tk=") + std::to_wstring(a) + L"." + std::to_wstring(b) + L"&q=" + std::wstring(text);
}

extern "C"
{
	/**
	* Param sentence: pointer to sentence received by NextHooker (UTF-16).
	* You should not modify this sentence. If you want NextHooker to receive a modified sentence, copy it into your own buffer and return that.
	* Param miscInfo: pointer to start of singly linked list containing misc info about the sentence.
	* Return value: pointer to sentence NextHooker takes for future processing and display.
	* Return 'sentence' unless you created a new sentence/buffer as mentioned above.
	* NextHooker will display the sentence after all extensions have had a chance to process and/or modify it.
	* THIS FUNCTION MAY BE RUN SEVERAL TIMES CONCURRENTLY: PLEASE ENSURE THAT IT IS THREAD SAFE!
	*/
	__declspec(dllexport) const wchar_t* OnNewSentence(const wchar_t* sentence, const InfoForExtension* miscInfo)
	{
		static HINTERNET internet = NULL;
		if (!internet) internet = WinHttpOpen(L"Mozilla/5.0 NextHooker", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
		static unsigned int TKK = 0;
		
		wchar_t error[] = L"Error while translating.";
		wchar_t translation[10000] = {};
		wchar_t* message = error;

		if (wcslen(sentence) > 2000 || GetProperty("text number", miscInfo) == 0) return sentence;

		if (internet)
		{
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
				if (HINTERNET request = WinHttpOpenRequest(connection, L"GET", GetTranslationUri(sentence, TKK).c_str(), NULL, NULL, NULL, WINHTTP_FLAG_ESCAPE_DISABLE | WINHTTP_FLAG_SECURE))
				{
					if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
					{
						DWORD bytesRead;
						char buffer[10000] = {};
						WinHttpReceiveResponse(request, NULL);
						WinHttpReadData(request, buffer, 10000, &bytesRead);
						// Response formatted as JSON: starts with '[[["'
						MultiByteToWideChar(CP_UTF8, 0, buffer + 4, (int)((strstr(buffer, "\",\"")) - (buffer + 4)), translation, 10000);
						message = translation;
						for (int i = -1; translation[++i];) if (translation[i] == L'\\') translation[i] = 0x200b;
					}
					WinHttpCloseHandle(request);
				}
				WinHttpCloseHandle(connection);
			}
		}

		wchar_t* newSentence = (wchar_t*)malloc((wcslen(sentence) + 3 + wcslen(message)) * sizeof(wchar_t));
		swprintf(newSentence, wcslen(sentence) + 3 + wcslen(message), L"%s%s%s", sentence, L"\r\n", message);
		return newSentence;
	}
}
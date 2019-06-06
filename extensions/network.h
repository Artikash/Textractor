#pragma once

#include "util.h"
#include <winhttp.h>

using InternetHandle = AutoHandle<Functor<WinHttpCloseHandle>>;

inline std::optional<std::wstring> ReceiveHttpRequest(HINTERNET request)
{
	WinHttpReceiveResponse(request, NULL);
	std::string data;
	DWORD dwSize, dwDownloaded;
	do
	{
		dwSize = 0;
		WinHttpQueryDataAvailable(request, &dwSize);
		if (!dwSize) break;
		std::vector<char> buffer(dwSize);
		WinHttpReadData(request, buffer.data(), dwSize, &dwDownloaded);
		data.append(buffer.data(), dwDownloaded);
	} while (dwSize > 0);

	if (data.empty()) return {};
	return StringToWideString(data);
}

inline void Unescape(std::wstring& text)
{
	for (int i = 0; i < text.size(); ++i)
	{
		if (text[i] == L'\\')
		{
			text[i] = 0x200b;
			if (text[i + 1] == L'r') text[i + 1] = 0x200b; // for some reason \r gets displayed as a newline
			if (text[i + 1] == L'n') text[i + 1] = L'\n';
			if (text[i + 1] == L't') text[i + 1] = L'\t';
		}
	}
}


class RateLimiter
{
public:
	RateLimiter(int tokenCount, int delay) : tokenCount(tokenCount), delay(delay) {}

	bool Request()
	{
		auto tokens = this->tokens.Acquire();
		tokens->push_back(GetTickCount());
		if (tokens->size() > tokenCount * 5) tokens->erase(tokens->begin(), tokens->begin() + tokenCount * 3);
		tokens->erase(std::remove_if(tokens->begin(), tokens->end(), [this](DWORD token) { return GetTickCount() - token > delay; }), tokens->end());
		return tokens->size() < tokenCount;
	}

	const int tokenCount, delay;

private:
	Synchronized<std::vector<DWORD>> tokens;
};

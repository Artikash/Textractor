#pragma once

#include "util.h"
#include <winhttp.h>

using InternetHandle = AutoHandle<Functor<WinHttpCloseHandle>>;

std::optional<std::wstring> ReceiveHttpRequest(HINTERNET request)
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
		data += std::string(buffer.data(), dwDownloaded);
	} while (dwSize > 0);

	if (data.empty()) return {};
	return StringToWideString(data);
}

void Escape(std::wstring& text)
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

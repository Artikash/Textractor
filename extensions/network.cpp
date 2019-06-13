#include "network.h"
#include "util.h"

HttpRequest::HttpRequest(
	const wchar_t* agentName,
	const wchar_t* serverName,
	const wchar_t* action,
	const wchar_t* objectName,
	DWORD requestFlags,
	const wchar_t* httpVersion,
	const wchar_t* referrer,
	const wchar_t** acceptTypes,
	const wchar_t* headers,
	void* body,
	DWORD bodyLength
)
{
	static std::atomic<HINTERNET> internet = NULL;
	if (!internet) internet = WinHttpOpen(agentName, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
	if (internet)
		if (InternetHandle connection = WinHttpConnect(internet, serverName, INTERNET_DEFAULT_HTTPS_PORT, 0))
			if (InternetHandle request = WinHttpOpenRequest(connection, action, objectName, httpVersion, referrer, acceptTypes, requestFlags))
				if (WinHttpSendRequest(request, headers, -1UL, body, bodyLength, bodyLength, NULL))
				{
					WinHttpReceiveResponse(request, NULL);
					std::string data;
					DWORD availableSize, downloadedSize;
					do
					{
						availableSize = 0;
						WinHttpQueryDataAvailable(request, &availableSize);
						if (!availableSize) break;
						std::vector<char> buffer(availableSize);
						WinHttpReadData(request, buffer.data(), availableSize, &downloadedSize);
						data.append(buffer.data(), downloadedSize);
					} while (availableSize > 0);
					response = StringToWideString(data);
					this->connection = std::move(connection);
					this->request = std::move(request);
				}
				else errorCode = GetLastError();
			else errorCode = GetLastError();
		else errorCode = GetLastError();
	else errorCode = GetLastError();
}

std::wstring Escape(const std::wstring& text)
{
	std::wstring escaped;
	for (unsigned char ch : WideStringToString(text)) escaped += FormatString(L"%%%02X", (int)ch);
	return escaped;
}

void Unescape(std::wstring& text)
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

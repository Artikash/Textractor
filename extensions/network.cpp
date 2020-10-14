#include "network.h"

HttpRequest::HttpRequest(
	const wchar_t* agentName,
	const wchar_t* serverName,
	const wchar_t* action,
	const wchar_t* objectName,
	std::string body,
	const wchar_t* headers,
	const wchar_t* referrer,
	DWORD requestFlags,
	const wchar_t* httpVersion,
	const wchar_t** acceptTypes,
	DWORD port
)
{
	static std::atomic<HINTERNET> internet = NULL;
	if (!internet) internet = WinHttpOpen(agentName, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
	if (internet)
		if (InternetHandle connection = WinHttpConnect(internet, serverName, port, 0))
			if (InternetHandle request = WinHttpOpenRequest(connection, action, objectName, httpVersion, referrer, acceptTypes, requestFlags))
				if (WinHttpSendRequest(request, headers, -1UL, body.empty() ? NULL : body.data(), body.size(), body.size(), NULL))
				{
					WinHttpReceiveResponse(request, NULL);

					//DWORD size = 0;
					//WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &size, WINHTTP_NO_HEADER_INDEX);
					//this->headers.resize(size);
					//WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, this->headers.data(), &size, WINHTTP_NO_HEADER_INDEX);
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

namespace JSON
{
	void Unescape(std::wstring& text)
	{
		for (int i = 0; i < text.size(); ++i)
		{
			if (text[i] == L'\\')
			{
				text[i] = 0;
				if (text[i + 1] == L'r') text[i + 1] = 0; // for some reason \r gets displayed as a newline
				if (text[i + 1] == L'n') text[i + 1] = L'\n';
				if (text[i + 1] == L't') text[i + 1] = L'\t';
				if (text[i + 1] == L'\\') ++i;
			}
		}
		text.erase(std::remove(text.begin(), text.end(), 0), text.end());
	}

	std::string Escape(const std::wstring& text)
	{
		std::string escaped = WideStringToString(text);
		int oldSize = escaped.size();
		escaped.resize(escaped.size() + std::count_if(escaped.begin(), escaped.end(), [](char ch) { return ch == '\n' || ch == '\r' || ch == '\t' || ch == '\\' || ch == '"'; }));
		auto out = escaped.rbegin();
		for (int i = oldSize - 1; i >= 0; --i)
		{
			if (escaped[i] == '\n') *out++ = 'n';
			else if (escaped[i] == '\t') *out++ = 't';
			else if (escaped[i] == '\r') *out++ = 'r';
			else if (escaped[i] == '\\' || escaped[i] == '"') *out++ = escaped[i];
			else
			{
				*out++ = escaped[i];
				continue;
			}
			*out++ = '\\';
		}
		escaped.erase(std::remove_if(escaped.begin(), escaped.end(), [](unsigned char ch) { return ch < 0x20; }), escaped.end());
		return escaped;
	}
}

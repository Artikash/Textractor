#pragma once

#include <winhttp.h>

using InternetHandle = AutoHandle<Functor<WinHttpCloseHandle>>;

struct HttpRequest
{
	HttpRequest(
		const wchar_t* agentName,
		const wchar_t* serverName,
		const wchar_t* action,
		const wchar_t* objectName,
		std::string body = "",
		const wchar_t* headers = NULL,
		const wchar_t* referrer = NULL,
		DWORD requestFlags = WINHTTP_FLAG_SECURE | WINHTTP_FLAG_ESCAPE_DISABLE,
		const wchar_t* httpVersion = NULL,
		const wchar_t** acceptTypes = NULL,
		DWORD port = INTERNET_DEFAULT_PORT
	);
	operator bool() { return errorCode == ERROR_SUCCESS; }

	std::wstring response;
	std::wstring headers;
	InternetHandle connection = NULL;
	InternetHandle request = NULL;
	DWORD errorCode = ERROR_SUCCESS;
};

std::wstring Escape(const std::wstring& text);

namespace JSON
{
	void Unescape(std::wstring& text);
	std::string Escape(const std::wstring& text);
}

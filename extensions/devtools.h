#include "qtcommon.h"
#include "network.h"

namespace DevTools
{
	void Start(const std::wstring& path, std::function<void(QString)> statusChanged, bool headless, int port);
	void Close();
	bool Connected();
	JSON::Value<wchar_t> SendRequest(const std::wstring& method, const std::wstring& params = L"{}");
	void StartListening(const std::wstring& method);
	std::vector<JSON::Value<wchar_t>> ListenResults(const std::wstring& method);
	void StopListening(const std::wstring& method);
}

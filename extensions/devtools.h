#include "qtcommon.h"
#include "network.h"

namespace DevTools
{
	void Start(const std::wstring& path, std::function<void(QString)> statusChanged, bool headless);
	void Close();
	bool Connected();
	JSON::Value<wchar_t> SendRequest(const std::wstring& method, const std::wstring& params = L"{}");
}

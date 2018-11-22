#include "util.h"
#include "text.h"
#include "host.h"

namespace Util
{
	std::optional<std::wstring> GetClipboardText()
	{
		if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) return {};
		if (!OpenClipboard(NULL)) return {};

		if (HANDLE clipboardHandle = GetClipboardData(CF_UNICODETEXT))
		{
			std::wstring ret = (wchar_t*)GlobalLock(clipboardHandle);
			GlobalUnlock(clipboardHandle);
			CloseClipboard();
			return ret;
		}
		CloseClipboard();
		return {};
	}

	std::wstring StringToWideString(std::string text, UINT encoding)
	{
		std::wstring ret(text.size() + 1, 0);
		if (int len = MultiByteToWideChar(encoding, 0, text.c_str(), -1, ret.data(), ret.size()))
		{
			ret.resize(len - 1);
			return ret;
		}
		else
		{
			Host::AddConsoleOutput(INVALID_CODEPAGE);
			return L"";
		}
	}

	bool RemoveRepetition(std::wstring& text)
	{
		wchar_t* end = text.data() + text.size();
		for (int len = text.size() / 3; len > 6; --len)
			if (wcsncmp(end - len * 3, end - len * 2, len) == 0 && wcsncmp(end - len * 3, end - len * 1, len) == 0)
				return true | RemoveRepetition(text = end - len);
		return false;
	}
}
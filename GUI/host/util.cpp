#include "util.h"
#include "types.h"
#include <Psapi.h>

namespace Util
{
	std::optional<std::wstring> GetModuleFilename(DWORD processId, HMODULE module)
	{
		if (AutoHandle<> process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId))
		{
			std::vector<wchar_t> buffer(MAX_PATH);
			if (GetModuleFileNameExW(process, module, buffer.data(), MAX_PATH)) return buffer.data();
			return {};
		}
		return {};
	}

	std::optional<std::wstring> GetModuleFilename(HMODULE module)
	{
		std::vector<wchar_t> buffer(MAX_PATH);
		if (GetModuleFileNameW(module, buffer.data(), MAX_PATH)) return buffer.data();
		return {};
	}

	std::optional<std::wstring> GetClipboardText()
	{
		if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) return {};
		if (!OpenClipboard(NULL)) return {};

		std::optional<std::wstring> ret;
		if (AutoHandle<Functor<GlobalUnlock>> clipboard = GetClipboardData(CF_UNICODETEXT)) ret = (wchar_t*)GlobalLock(clipboard);
		CloseClipboard();
		return ret;
	}

	std::optional<std::wstring> StringToWideString(std::string text, UINT encoding)
	{
		std::vector<wchar_t> buffer(text.size() + 1);
		if (MultiByteToWideChar(encoding, 0, text.c_str(), -1, buffer.data(), buffer.size())) return buffer.data();
		return {};
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

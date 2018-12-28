#pragma once

#include "common.h"

namespace Util
{
	std::optional<std::wstring> GetModuleFilename(DWORD processId, HMODULE module = NULL);
	std::optional<std::wstring> GetModuleFilename(HMODULE module = NULL);
	std::optional<std::wstring> GetClipboardText();
	std::optional<std::wstring> StringToWideString(std::string text, UINT encoding = CP_UTF8);
	// return true if repetition found (see https://github.com/Artikash/Textractor/issues/40)
	bool RemoveRepetition(std::wstring& text);
}

#pragma once

#include "common.h"
#include "types.h"

namespace Util
{
	std::optional<std::wstring> GetModuleFilename(DWORD processId, HMODULE module = NULL);
	std::optional<std::wstring> GetModuleFilename(HMODULE module = NULL);
	std::vector<DWORD> GetAllProcessIds();
	std::optional<std::wstring> GetClipboardText();
	std::optional<std::wstring> StringToWideString(const std::string& text, UINT encoding = CP_UTF8);
	// return true if repetition found (see https://github.com/Artikash/Textractor/issues/40)
	bool RemoveRepetition(std::wstring& text);
	std::optional<HookParam> ParseCode(std::wstring code);
	std::wstring GenerateCode(HookParam hp, DWORD processId);
}

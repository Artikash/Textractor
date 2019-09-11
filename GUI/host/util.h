#pragma once

#include "common.h"
#include "types.h"

namespace Util
{
	std::optional<std::wstring> GetModuleFilename(DWORD processId, HMODULE module = NULL);
	std::optional<std::wstring> GetModuleFilename(HMODULE module = NULL);
	std::vector<std::pair<DWORD, std::optional<std::wstring>>> GetAllProcesses();
	std::optional<std::wstring> GetClipboardText();
	std::optional<std::wstring> StringToWideString(const std::string& text, UINT encoding = CP_UTF8);
	std::optional<HookParam> ParseCode(std::wstring code);
	std::wstring GenerateCode(HookParam hp, DWORD processId = 0);
}

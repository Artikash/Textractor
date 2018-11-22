#pragma once

#include "common.h"

namespace Util
{
	std::optional<std::wstring> GetClipboardText();
	std::wstring StringToWideString(std::string text, UINT encoding = CP_UTF8);
}

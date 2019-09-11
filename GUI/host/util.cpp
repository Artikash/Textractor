#include "util.h"
#include <sstream>
#include <Psapi.h>

namespace
{
	std::optional<HookParam> ParseRCode(std::wstring RCode)
	{
		std::wsmatch match;
		HookParam hp = {};
		hp.type |= DIRECT_READ;

		// {S|Q|V}
		switch (RCode[0])
		{
		case L'S':
			break;
		case L'Q':
			hp.type |= USING_UNICODE;
			break;
		case L'V':
			hp.type |= USING_UTF8;
			break;
		default:
			return {};
		}
		RCode.erase(0, 1);

		// [null_length<]
		if (std::regex_search(RCode, match, std::wregex(L"^([0-9]+)<")))
		{
			hp.null_length = std::stoi(match[1]);
			RCode.erase(0, match[0].length());
		}

		// [codepage#]
		if (std::regex_search(RCode, match, std::wregex(L"^([0-9]+)#")))
		{
			hp.codepage = std::stoi(match[1]);
			RCode.erase(0, match[0].length());
		}

		// @addr
		if (!std::regex_match(RCode, match, std::wregex(L"@([[:xdigit:]]+)"))) return {};
		hp.address = std::stoull(match[1], nullptr, 16);
		return hp;
	}

	std::optional<HookParam> ParseHCode(std::wstring HCode)
	{
		std::wsmatch match;
		HookParam hp = {};

		// {A|B|W|S|Q|V}
		switch (HCode[0])
		{
		case L'S':
			hp.type |= USING_STRING;
			break;
		case L'A':
			hp.type |= BIG_ENDIAN;
			hp.length_offset = 1;
			break;
		case L'B':
			hp.length_offset = 1;
			break;
		case L'Q':
			hp.type |= USING_STRING | USING_UNICODE;
			break;
		case L'W':
			hp.type |= USING_UNICODE;
			hp.length_offset = 1;
			break;
		case L'V':
			hp.type |= USING_STRING | USING_UTF8;
			break;
		default:
			return {};
		}
		HCode.erase(0, 1);

		if ((hp.type & USING_STRING))
		{
			if (HCode[0] == L'F')
			{
				hp.type |= FULL_STRING;
				HCode.erase(0, 1);
			}

			// [null_length<]
			if (std::regex_search(HCode, match, std::wregex(L"^([0-9]+)<")))
			{
				hp.null_length = std::stoi(match[1]);
				HCode.erase(0, match[0].length());
			}
		}

		// [N]
		if (HCode[0] == L'N')
		{
			hp.type |= NO_CONTEXT;
			HCode.erase(0, 1);
		}

		// [codepage#]
		if (std::regex_search(HCode, match, std::wregex(L"^([0-9]+)#")))
		{
			hp.codepage = std::stoi(match[1]);
			HCode.erase(0, match[0].length());
		}

		// [padding+]
		if (std::regex_search(HCode, match, std::wregex(L"^([[:xdigit:]]+)\\+")))
		{
			hp.padding = std::stoull(match[1], nullptr, 16);
			HCode.erase(0, match[0].length());
		}

		// data_offset
		if (!std::regex_search(HCode, match, std::wregex(L"^-?[[:xdigit:]]+"))) return {};
		hp.offset = std::stoi(match[0], nullptr, 16);
		HCode.erase(0, match[0].length());

		// [*deref_offset1]
		if (std::regex_search(HCode, match, std::wregex(L"^\\*(-?[[:xdigit:]]+)")))
		{
			hp.type |= DATA_INDIRECT;
			hp.index = std::stoi(match[1], nullptr, 16);
			HCode.erase(0, match[0].length());
		}

		// [:split_offset[*deref_offset2]]
		if (std::regex_search(HCode, match, std::wregex(L"^:(-?[[:xdigit:]]+)")))
		{
			hp.type |= USING_SPLIT;
			hp.split = std::stoi(match[1], nullptr, 16);
			HCode.erase(0, match[0].length());

			if (std::regex_search(HCode, match, std::wregex(L"^\\*(-?[[:xdigit:]]+)")))
			{
				hp.type |= SPLIT_INDIRECT;
				hp.split_index = std::stoi(match[1], nullptr, 16);
				HCode.erase(0, match[0].length());
			}
		}

		// @addr[:module[:func]]
		if (!std::regex_match(HCode, match, std::wregex(L"@([[:xdigit:]]+)(:.+?)?(:.+)?"))) return {};
		hp.address = std::stoull(match[1], nullptr, 16);
		if (match[2].matched)
		{
			hp.type |= MODULE_OFFSET;
			wcsncpy_s(hp.module, match[2].str().erase(0, 1).c_str(), MAX_MODULE_SIZE - 1);
		}
		if (match[3].matched)
		{
			hp.type |= FUNCTION_OFFSET;
			std::wstring func = match[3];
			strncpy_s(hp.function, std::string(func.begin(), func.end()).erase(0, 1).c_str(), MAX_MODULE_SIZE - 1);
		}

		// ITH has registers offset by 4 vs AGTH: need this to correct
		if (hp.offset < 0) hp.offset -= 4;
		if (hp.split < 0) hp.split -= 4;

		return hp;
	}

	std::wstring HexString(int64_t num)
	{
		if (num < 0) return FormatString(L"-%I64X", -num);
		return FormatString(L"%I64X", num);
	}

	std::wstring GenerateRCode(HookParam hp)
	{
		std::wstring RCode = L"R";

		if (hp.type & USING_UNICODE)
		{
			RCode += L'Q';
			if (hp.null_length != 0) RCode += std::to_wstring(hp.null_length) + L'<';
		}
		else
		{
			RCode += L'S';
			if (hp.null_length != 0) RCode += std::to_wstring(hp.null_length) + L'<';
			if (hp.codepage != 0) RCode += std::to_wstring(hp.codepage) + L'#';
		}

		RCode += L'@' + HexString(hp.address);

		return RCode;
	}

	std::wstring GenerateHCode(HookParam hp, DWORD processId)
	{
		std::wstring HCode = L"H";

		if (hp.type & USING_UNICODE)
		{
			if (hp.type & USING_STRING) HCode += L'Q';
			else HCode += L'W';
		}
		else
		{
			if (hp.type & USING_STRING) HCode += L'S';
			else if (hp.type & BIG_ENDIAN) HCode += L'A';
			else HCode += L'B';
		}

		if (hp.type & FULL_STRING) HCode += L'F';

		if (hp.null_length != 0) HCode += std::to_wstring(hp.null_length) + L'<';

		if (hp.type & NO_CONTEXT) HCode += L'N';
		if (hp.text_fun || hp.filter_fun || hp.hook_fun || hp.length_fun) HCode += L'X'; // no AGTH equivalent

		if (hp.codepage != 0 && !(hp.type & USING_UNICODE)) HCode += std::to_wstring(hp.codepage) + L'#';

		if (hp.padding) HCode += HexString(hp.padding) + L'+';

		if (hp.offset < 0) hp.offset += 4;
		if (hp.split < 0) hp.split += 4;

		HCode += HexString(hp.offset);
		if (hp.type & DATA_INDIRECT) HCode += L'*' + HexString(hp.index);
		if (hp.type & USING_SPLIT) HCode += L':' + HexString(hp.split);
		if (hp.type & SPLIT_INDIRECT) HCode += L'*' + HexString(hp.split_index);

		// Attempt to make the address relative
		if (processId && !(hp.type & MODULE_OFFSET))
			if (AutoHandle<> process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId))
				if (MEMORY_BASIC_INFORMATION info = {}; VirtualQueryEx(process, (LPCVOID)hp.address, &info, sizeof(info)))
					if (auto moduleName = Util::GetModuleFilename(processId, (HMODULE)info.AllocationBase))
					{
						hp.type |= MODULE_OFFSET;
						hp.address -= (uint64_t)info.AllocationBase;
						wcsncpy_s(hp.module, moduleName->c_str() + moduleName->rfind(L'\\') + 1, MAX_MODULE_SIZE - 1);
					}

		HCode += L'@' + HexString(hp.address);
		if (hp.type & MODULE_OFFSET) HCode += L':' + std::wstring(hp.module);
		if (hp.type & FUNCTION_OFFSET) HCode += L':' + std::wstring(hp.function, hp.function + MAX_MODULE_SIZE);

		return HCode;
	}
}

namespace Util
{
	std::optional<std::wstring> GetModuleFilename(DWORD processId, HMODULE module)
	{
		std::vector<wchar_t> buffer(MAX_PATH);
		if (AutoHandle<> process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId)) 
			if (GetModuleFileNameExW(process, module, buffer.data(), MAX_PATH)) return buffer.data();
		return {};
	}

	std::optional<std::wstring> GetModuleFilename(HMODULE module)
	{
		std::vector<wchar_t> buffer(MAX_PATH);
		if (GetModuleFileNameW(module, buffer.data(), MAX_PATH)) return buffer.data();
		return {};
	}

	std::vector<std::pair<DWORD, std::optional<std::wstring>>> GetAllProcesses()
	{
		std::vector<DWORD> processIds(10000);
		DWORD spaceUsed = 0;
		EnumProcesses(processIds.data(), 10000 * sizeof(DWORD), &spaceUsed);
		std::vector<std::pair<DWORD, std::optional<std::wstring>>> processes;
		for (int i = 0; i < spaceUsed / sizeof(DWORD); ++i) processes.push_back({ processIds[i], Util::GetModuleFilename(processIds[i]) });
		return processes;
	}

	std::optional<std::wstring> GetClipboardText()
	{
		if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) return {};
		if (!OpenClipboard(NULL)) return {};

		std::optional<std::wstring> text;
		if (AutoHandle<Functor<GlobalUnlock>> clipboard = GetClipboardData(CF_UNICODETEXT)) text = (wchar_t*)GlobalLock(clipboard);
		CloseClipboard();
		return text;
	}

	std::optional<std::wstring> StringToWideString(const std::string& text, UINT encoding)
	{
		std::vector<wchar_t> buffer(text.size() + 1);
		if (int length = MultiByteToWideChar(encoding, 0, text.c_str(), text.size() + 1, buffer.data(), buffer.size())) 
			return std::wstring(buffer.data(), length - 1);
		return {};
	}

	std::optional<HookParam> ParseCode(std::wstring code)
	{
		if (code[0] == L'/') code.erase(0, 1); // legacy/AGTH compatibility
		if (code[0] == L'R') return ParseRCode(code.erase(0, 1));
		else if (code[0] == L'H') return ParseHCode(code.erase(0, 1));
		return {};
	}

	std::wstring GenerateCode(HookParam hp, DWORD processId)
	{
		return hp.type & DIRECT_READ ? GenerateRCode(hp) : GenerateHCode(hp, processId);
	}

	TEST(
		assert(StringToWideString(u8"こんにちは").value() == L"こんにちは"),
		assert(HexString(-12) == L"-C"),
		assert(HexString(12) == L"C"),
		assert(ParseCode(L"/HQN936#-c*C:C*1C@4AA:gdi.dll:GetTextOutA")),
		assert(ParseCode(L"HB4@0")),
		assert(ParseCode(L"/RS65001#@44")),
		assert(!ParseCode(L"HQ@4")),
		assert(!ParseCode(L"/RW@44")),
		assert(!ParseCode(L"/HWG@33"))
	);
}

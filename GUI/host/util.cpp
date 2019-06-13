#include "util.h"
#include "host.h"
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

	std::optional<HookParam> ParseSCode(std::wstring SCode)
	{
		std::wsmatch match;
		HookParam hp = {};
		hp.type |= READ_SEARCH;

		// [codepage#]
		if (std::regex_search(SCode, match, std::wregex(L"^([0-9]+)#")))
		{
			hp.codepage = std::stoi(match[1]);
			SCode.erase(0, match[0].length());
		}
		else
		{
			hp.codepage = Host::defaultCodepage;
		}

		wcsncpy_s(hp.text, SCode.c_str(), MAX_MODULE_SIZE - 1);

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

		// [null_length<]
		if ((hp.type & USING_STRING) && std::regex_search(HCode, match, std::wregex(L"^([0-9]+)<")))
		{
			hp.null_length = std::stoi(match[1]);
			HCode.erase(0, match[0].length());
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

	std::wstring HexString(int64_t num) // only needed for signed nums
	{
		return (std::wstringstream() << std::uppercase << std::hex << (num < 0 ? "-" : "") << abs(num)).str();
	}

	std::wstring GenerateRCode(HookParam hp)
	{
		std::wstringstream RCode;
		RCode << "R";

		if (hp.type & USING_UNICODE)
		{
			RCode << "Q";
			if (hp.null_length != 0) RCode << hp.null_length << "<";
		}
		else
		{
			RCode << "S";
			if (hp.null_length != 0) RCode << hp.null_length << "<";
			if (hp.codepage != 0) RCode << hp.codepage << "#";
		}

		RCode << std::uppercase << std::hex;

		RCode << "@" << hp.address;

		return RCode.str();
	}

	std::wstring GenerateHCode(HookParam hp, DWORD processId)
	{
		std::wstringstream HCode;
		HCode << "H";

		if (hp.type & USING_UNICODE)
		{
			if (hp.type & USING_STRING) HCode << "Q";
			else HCode << "W";
		}
		else
		{
			if (hp.type & USING_STRING) HCode << "S";
			else if (hp.type & BIG_ENDIAN) HCode << "A";
			else HCode << "B";
		}

		if (hp.null_length != 0) HCode << hp.null_length << "<";

		if (hp.type & NO_CONTEXT) HCode << "N";
		if (hp.text_fun || hp.filter_fun || hp.hook_fun) HCode << "X"; // no AGTH equivalent

		if (hp.codepage != 0 && !(hp.type & USING_UNICODE)) HCode << hp.codepage << "#";

		HCode << std::uppercase << std::hex;

		if (hp.padding) HCode << hp.padding << "+";

		if (hp.offset < 0) hp.offset += 4;
		if (hp.split < 0) hp.split += 4;

		HCode << HexString(hp.offset);
		if (hp.type & DATA_INDIRECT) HCode << "*" << HexString(hp.index);
		if (hp.type & USING_SPLIT) HCode << ":" << HexString(hp.split);
		if (hp.type & SPLIT_INDIRECT) HCode << "*" << HexString(hp.split_index);

		// Attempt to make the address relative
		if (!(hp.type & MODULE_OFFSET))
			if (AutoHandle<> process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId))
				if (MEMORY_BASIC_INFORMATION info = {}; VirtualQueryEx(process, (LPCVOID)hp.address, &info, sizeof(info)))
					if (auto moduleName = Util::GetModuleFilename(processId, (HMODULE)info.AllocationBase))
					{
						hp.type |= MODULE_OFFSET;
						hp.address -= (uint64_t)info.AllocationBase;
						wcsncpy_s(hp.module, moduleName->c_str() + moduleName->rfind(L'\\') + 1, MAX_MODULE_SIZE - 1);
					}

		HCode << "@" << hp.address;
		if (hp.type & MODULE_OFFSET) HCode << ":" << hp.module;
		if (hp.type & FUNCTION_OFFSET) HCode << ":" << hp.function;

		return HCode.str();
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

	std::vector<DWORD> GetAllProcessIds()
	{
		std::vector<DWORD> processIds(10000);
		DWORD spaceUsed = 0;
		EnumProcesses(processIds.data(), 10000 * sizeof(DWORD), &spaceUsed);
		processIds.resize(spaceUsed / sizeof(DWORD));
		return processIds;
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

	bool RemoveRepetition(std::wstring& text)
	{
		wchar_t* end = text.data() + text.size();
		for (int length = text.size() / 3; length > 6; --length)
			if (memcmp(end - length * 3, end - length * 2, length * sizeof(wchar_t)) == 0 && memcmp(end - length * 3, end - length * 1, length * sizeof(wchar_t)) == 0)
				return RemoveRepetition(text = std::wstring(end - length, length)), true;
		return false;
	}

	std::optional<HookParam> ParseCode(std::wstring code)
	{
		if (code[0] == L'/') code.erase(0, 1); // legacy/AGTH compatibility
		if (code[0] == L'R') return ParseRCode(code.erase(0, 1));
		else if (code[0] == L'S') return ParseSCode(code.erase(0, 1));
		else if (code[0] == L'H') return ParseHCode(code.erase(0, 1));
		return {};
	}

	std::wstring GenerateCode(HookParam hp, DWORD processId)
	{
		return hp.type & DIRECT_READ ? GenerateRCode(hp) : GenerateHCode(hp, processId);
	}

	TEST(
		assert(StringToWideString(u8"こんにちは").value() == L"こんにちは"),
		assert(ParseCode(L"/HQN936#-c*C:C*1C@4AA:gdi.dll:GetTextOutA")),
		assert(ParseCode(L"HB4@0")),
		assert(ParseCode(L"/RS65001#@44")),
		assert(!ParseCode(L"HQ@4")),
		assert(!ParseCode(L"/RW@44")),
		assert(!ParseCode(L"/HWG@33"))
	);
}

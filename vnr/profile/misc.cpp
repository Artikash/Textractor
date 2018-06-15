#include "misc.h"
#include <regex>
#include <memory>
#include "host/host.h"
#include "vnrhook/include/const.h"
#include "vnrhook/include/types.h"

DWORD Hash(const std::wstring& module, int length)
{
	DWORD hash = 0;
	auto end = (length < 0 || static_cast<size_t>(length) > module.length()) ?
		module.end() :
		module.begin() + length;
	for (auto it = module.begin(); it != end; ++it)
		hash = _rotr(hash, 7) + *it;
	return hash;
}

bool Parse(const std::wstring& cmd, HookParam& hp)
{
	using std::wregex;
	using std::regex_search;
	// /H[X]{A|B|W|S|Q}[N][data_offset[*drdo]][:sub_offset[*drso]]@addr[:[module[:{name|#ordinal}]]]
	wregex rx(L"^X?([ABWSQ])(N)?", wregex::icase);
	std::match_results<std::wstring::const_iterator> m;
	auto start = cmd.begin();
	auto end = cmd.end();
	bool result = regex_search(start, end, m, rx);
	if (!result)
		return result;
	start = m[0].second;
	if (m[2].matched)
		hp.type |= NO_CONTEXT;

	switch (m[1].first[0])
	{
	case L's':
	case L'S':
		hp.type |= USING_STRING;
		break;
	case L'e':
	case L'E':
		hp.type |= STRING_LAST_CHAR;
	case L'a':
	case L'A':
		hp.type |= BIG_ENDIAN;
		hp.length_offset = 1;
		break;
	case L'b':
	case L'B':
		hp.length_offset = 1;
		break;
	case L'h':
	case L'H':
		hp.type |= PRINT_DWORD;
	case L'q':
	case L'Q':
		hp.type |= USING_STRING | USING_UNICODE;
		break;
	case L'l':
	case L'L':
		hp.type |= STRING_LAST_CHAR;
	case L'w':
	case L'W':
		hp.type |= USING_UNICODE;
		hp.length_offset = 1;
		break;
	default:
		break;
	}

	// [data_offset[*drdo]]
	std::wstring data_offset(L"(-?[[:xdigit:]]+)"), drdo(L"(\\*-?[[:xdigit:]]+)?");
	rx = wregex(L"^" + data_offset + drdo, wregex::icase);
	result = regex_search(start, end, m, rx);
	if (result)
	{
		start = m[0].second;
		hp.offset = std::stoul(m[1].str(), NULL, 16);
		if (m[2].matched)
		{
			hp.type |= DATA_INDIRECT;
			hp.index = std::stoul(m[2].str().substr(1), NULL, 16);
		}
	}

	// [:sub_offset[*drso]]
	std::wstring sub_offset(L"(-?[[:xdigit:]]+)"), drso(L"(\\*-?[[:xdigit:]]+)?");
	rx = wregex(L"^:" + sub_offset + drso, wregex::icase);
	result = regex_search(start, end, m, rx);
	if (result)
	{
		start = m[0].second;
		hp.type |= USING_SPLIT;
		hp.split = std::stoul(m[1].str(), NULL, 16);
		if (m[2].matched)
		{
			hp.type |= SPLIT_INDIRECT;
			hp.split_index = std::stoul(m[2].str().substr(1), NULL, 16);
		}
	}
	// @addr
	rx = wregex(L"^@[[:xdigit:]]+", wregex::icase);
	result = regex_search(start, end, m, rx);
	if (!result)
		return false;
	start = m[0].second;
	hp.address = std::stoul(m[0].str().substr(1), NULL, 16);
	if (hp.offset & 0x80000000)
		hp.offset -= 4;
	if (hp.split & 0x80000000)
		hp.split -= 4;

	// [:[module[:{name|#ordinal}]]]
	// ":"               -> module == NULL &% function == NULL
	// ""                -> MODULE_OFFSET && module == NULL && function == addr
	// ":GDI.dll"        -> MODULE_OFFSET && module != NULL
	// ":GDI.dll:strlen" -> MODULE_OFFSET | FUNCTION_OFFSET && module != NULL && function != NULL
	// ":GDI.dll:#123"   -> MODULE_OFFSET | FUNCTION_OFFSET && module != NULL && function != NULL
	std::wstring module(L"([^:[:space:]]+)"), name(L"[^:[:space:]]+"), ordinal(L"\\d+");
	rx = wregex(L"^:(" + module + L"(:" + name + L"|#" + ordinal + L")?)?$", wregex::icase);
	result = regex_search(start, end, m, rx);
	if (result) // :[module[:{name|#ordinal}]]
	{
		if (m[1].matched) // module
		{
			hp.type |= MODULE_OFFSET;
			std::wstring module = m[2];
			std::transform(module.begin(), module.end(), module.begin(), ::towlower);
			hp.module = Hash(module);
			if (m[3].matched) // :name|#ordinal
			{
				hp.type |= FUNCTION_OFFSET;
				hp.function = Hash(m[3].str().substr(1));
			}
		}
	}
	else
	{
		rx = wregex(L"^!([[:xdigit:]]+)(!([[:xdigit:]]+))?$", wregex::icase);
		result = regex_search(start, end, m, rx);
		if (result)
		{
			hp.type |= MODULE_OFFSET;
			hp.module = std::stoul(m[1].str(), NULL, 16);
			if (m[2].matched)
			{
				hp.type |= FUNCTION_OFFSET;
				hp.function = std::stoul(m[2].str().substr(1), NULL, 16);
			}
		}
		else
		{
			// Hack. Hook is relative to the executable. Store the original address in function.
			// hp.module == NULL && hp.function != NULL
			hp.type |= MODULE_OFFSET;
			hp.function = hp.address;
		}
	}
	return true;
}

std::wstring ParseCode(const HookParam& hp)
{
	std::wstring code(L"/H");
	WCHAR c;
	if (hp.type & PRINT_DWORD)
		c = L'H';
	else if (hp.type & USING_UNICODE)
	{
		if (hp.type & USING_STRING)
			c = L'Q';
		else if (hp.type & STRING_LAST_CHAR)
			c = L'L';
		else
			c = L'W';
	}
	else
	{
		if (hp.type & USING_STRING)
			c = L'S';
		else if (hp.type & BIG_ENDIAN)
			c = L'A';
		else if (hp.type & STRING_LAST_CHAR)
			c = L'E';
		else
			c = L'B';
	}
	code += c;
	if (hp.type & NO_CONTEXT)
		code += L'N';
	if (hp.offset >> 31)
		code += L'-' + ToHexString(-(hp.offset + 4));
	else
		code += ToHexString(hp.offset);
	if (hp.type & DATA_INDIRECT)
	{
		if (hp.index >> 31)
			code += L'*-' + ToHexString(-hp.index);
		else
			code += L'*' + ToHexString(hp.index);
	}
	if (hp.type & USING_SPLIT)
	{
		if (hp.split >> 31)
			code += L":-" + ToHexString(-(4 + hp.split));
		else
			code += L":" + ToHexString(hp.split);
	}
	if (hp.type & SPLIT_INDIRECT)
	{
		if (hp.split_index >> 31)
			code += L"*-" + ToHexString(-hp.split_index);
		else
			code += L"*" + ToHexString(hp.split_index);
	}
	if (hp.module)
	{
		code += L"@" + ToHexString(hp.address) + L"!" + ToHexString(hp.module);
		if (hp.function)
			code += L"!" + ToHexString(hp.function);
	}
	else
	{
		// Hack. The original address is stored in the function field
		// if (module == NULL && function != NULL).
		// MODULE_OFFSET and FUNCTION_OFFSET are removed from HookParam.type in
		// TextHook::UnsafeInsertHookCode() and can not be used here.
		if (hp.function)
			code += L"@" + ToHexString(hp.function);
		else
			code += L"@" + ToHexString(hp.address) + L":";
	}
	return code;
}


std::string toMultiByteString(const std::wstring& unicodeString)
{
	int cbMultiByte = WideCharToMultiByte(932, 0, unicodeString.c_str(), unicodeString.length(),
		NULL, 0, NULL, NULL);
	auto lpMultiByteStr = std::make_unique<CHAR[]>(cbMultiByte);
	WideCharToMultiByte(932, 0, unicodeString.c_str(), unicodeString.length(),
		lpMultiByteStr.get(), cbMultiByte, NULL, NULL);
	return std::string(lpMultiByteStr.get(), cbMultiByte);
}

std::wstring toUnicodeString(const std::string& mbString)
{
	int cchWideChar = MultiByteToWideChar(932, 0, mbString.c_str(), mbString.length(), NULL, 0);
	auto lpWideCharStr = std::make_unique<WCHAR[]>(cchWideChar);
	MultiByteToWideChar(932, 0, mbString.c_str(), mbString.length(), lpWideCharStr.get(), cchWideChar);
	return std::wstring(lpWideCharStr.get(), cchWideChar);
}

std::wstring GetHookNameByAddress(const ProcessRecord& pr, DWORD hook_address)
{
	std::wstring hook_name;
	WaitForSingleObject(pr.hookman_mutex, 0);
	auto hooks = (const Hook*)pr.hookman_map;
	for (int i = 0; i < MAX_HOOK; ++i)
	{
		auto& hook = hooks[i];
		if (hook.Address() == hook_address)
		{
			std::unique_ptr<CHAR[]> name(new CHAR[hook.NameLength()]);
			// name is zero terminated
			if (ReadProcessMemory(pr.process_handle, hooks[i].Name(), name.get(), hook.NameLength(), NULL))
				hook_name = toUnicodeString(name.get());
			break;
		}
	}
	ReleaseMutex(pr.hookman_mutex);
	return hook_name;
}

#pragma once

#include <Windows.h>
#include <string>
#include <sstream>

struct HookParam;
struct ProcessRecord;

bool Parse(const std::wstring& cmd, HookParam& hp);
DWORD Hash(const std::wstring& module, int length = -1);
std::wstring ParseCode(const HookParam& hp);
std::string toMultiByteString(const std::wstring& unicodeString);
std::wstring toUnicodeString(const std::string& mbString);
std::wstring GetHookNameByAddress(const ProcessRecord& pr, DWORD hook_address);

template <typename T>
std::wstring ToHexString(T i) {
	std::wstringstream ss;
	ss << std::uppercase << std::hex << i;
	return ss.str();
}

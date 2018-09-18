#pragma once

// v8.h
// 9/17/2018 Artikash
// Hooks for V8 JavaScript runtime
#include "common.h"
#include "types.h"

namespace V8
{
#pragma pack(1)
	struct V8String
	{
		BYTE filler[7];
		int length;
		wchar_t string[1];
	};
	void SpecialHookV8String(DWORD dwDatabase, HookParam* hp, BYTE, DWORD* data, DWORD* split, DWORD* len)
	{
		V8String* str = *(V8String**)data;
		*data = (DWORD)str->string;
		*len = str->length;
		if (hp->type & USING_SPLIT) *split = *(DWORD*)((BYTE*)hp->split + dwDatabase);
	}
	void HookV8Functions(HMODULE hModule)
	{
		const std::string V8_FUNCTIONS[] =
		{
			"",
			""
		};
	}
}
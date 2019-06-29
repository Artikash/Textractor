#pragma once

#include "common.h"

struct InfoForExtension
{
	const char* name;
	int64_t value;
};

struct SentenceInfo
{
	const InfoForExtension* infoArray;
	int64_t operator[](std::string propertyName)
	{
		for (auto info = infoArray; info->name; ++info) // nullptr name marks end of info array
			if (propertyName == info->name) return info->value;
		return *(int*)0xcccc = 0; // gives better error message than alternatives
	}

	inline static InfoForExtension DUMMY[2] = { { "text number", 1 } };
};

struct SKIP {};
inline void Skip() { throw SKIP(); }

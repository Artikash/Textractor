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
	// nullptr marks end of info array
	int64_t operator[](std::string propertyName)
	{
		for (auto info = infoArray; info->name != nullptr; ++info) if (propertyName == info->name) return info->value;
		throw;
	}

	inline static InfoForExtension DUMMY[2] = { { "hook address", 0 } };
};

struct SKIP {};
inline void Skip() { throw SKIP(); }

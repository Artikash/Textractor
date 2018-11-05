#pragma once

#include "common.h"

struct InfoForExtension
{
	const char* name;
	int64_t value;
	InfoForExtension* next;
};

struct SentenceInfo
{
	const InfoForExtension* list;
	// Traverse linked list to find info.
	int64_t operator[](std::string propertyName)
	{
		for (auto i = list; i != nullptr; i = i->next) if (propertyName == i->name) return i->value;
		throw;
	}
};

struct SKIP {};
inline void Skip() { throw SKIP(); }

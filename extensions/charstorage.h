#pragma once

#include "common.h"

template <typename C>
class CharStorage
{
public:
	CharStorage(size_t capacity = 0)
	{
		storage.reserve(capacity);
	}

	int Store(const std::basic_string<C>& string)
	{
		return storage.insert(storage.end(), string.c_str(), string.c_str() + string.size() + 1) - storage.begin();
	}

	void FreeExcess()
	{
		storage.shrink_to_fit();
	}

	const C* Retrieve(int handle) const
	{
		return storage.data() + handle;
	}

private:
	std::vector<C> storage;
};
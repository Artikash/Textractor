#pragma once

#include "common.h"
#include <iostream>

template <typename C>
class BlockMarkupLanguageIterator
{
	std::istreambuf_iterator<char> it;
};

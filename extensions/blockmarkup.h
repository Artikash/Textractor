#pragma once

#include "common.h"
#include <istream>

template <typename C, int DelimiterCount, int bufferStartSize = 200>
class BlockMarkupIterator
{
public:
	BlockMarkupIterator(std::istreambuf_iterator<char> it, const std::basic_string_view<C> (&delimiters)[DelimiterCount]) :
		it(it)
	{
		std::copy_n(delimiters, DelimiterCount, this->delimiters.begin());
	}
	std::optional<std::array<std::basic_string<C>, DelimiterCount>> Next()
	{
		std::array<std::basic_string<C>, DelimiterCount> results;
		std::basic_string<C> buffer;
		buffer.reserve(bufferStartSize);
		Find(buffer, delimiters[0]);
		buffer.clear();
		for (int i = 0; i < DelimiterCount; ++i)
		{
			const auto delimiter = i + 1 < DelimiterCount ? delimiters[i + 1] : end;
			if (!Find(buffer, delimiter)) return {};
			buffer.erase(buffer.size() - delimiter.size());
			results[i] = std::move(buffer);
			(buffer = {}).reserve(bufferStartSize);
		}
		return results;
	}

private:
	bool Find(std::basic_string<C>& result, std::basic_string_view<C> delimiter)
	{
		while (Read((result += C{}).back())) if (result.back() == '|' && result.find(delimiter, result.size() - delimiter.size()) != std::string::npos) return true;
		return false;
	}

	bool Read(C& out)
	{
		BYTE buffer[sizeof(C)];
		for (int i = 0; i < sizeof(C); ++i, ++it)
			if (it.equal({})) return false;
			else buffer[i] = *it;
		out = reinterpret_cast<C&>(buffer);
		return true;
	}

	static constexpr C endImpl[5] = { '|', 'E', 'N', 'D', '|' };
	static constexpr std::basic_string_view end{ endImpl, 5 };

	std::istreambuf_iterator<char> it;
	std::array<std::basic_string_view<C>, DelimiterCount> delimiters;
};

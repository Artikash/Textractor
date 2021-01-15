#pragma once

#include <winhttp.h>
#include <variant>

using InternetHandle = AutoHandle<Functor<WinHttpCloseHandle>>;

struct HttpRequest
{
	HttpRequest(
		const wchar_t* agentName,
		const wchar_t* serverName,
		const wchar_t* action,
		const wchar_t* objectName,
		std::string body = "",
		const wchar_t* headers = NULL,
		DWORD port = INTERNET_DEFAULT_PORT,
		const wchar_t* referrer = NULL,
		DWORD requestFlags = WINHTTP_FLAG_SECURE | WINHTTP_FLAG_ESCAPE_DISABLE,
		const wchar_t* httpVersion = NULL,
		const wchar_t** acceptTypes = NULL
	);
	operator bool() { return errorCode == ERROR_SUCCESS; }

	std::wstring response;
	std::wstring headers;
	InternetHandle connection = NULL;
	InternetHandle request = NULL;
	DWORD errorCode = ERROR_SUCCESS;
};

std::wstring Escape(const std::wstring& text);
std::string Escape(const std::string& text);

namespace JSON
{
	template <typename C>
	std::basic_string<C> Escape(std::basic_string<C> text)
	{
		int oldSize = text.size();
		text.resize(text.size() + std::count_if(text.begin(), text.end(), [](C ch) { return ch == '\n' || ch == '\r' || ch == '\t' || ch == '\\' || ch == '"'; }));
		auto out = text.rbegin();
		for (int i = oldSize - 1; i >= 0; --i)
		{
			if (text[i] == '\n') *out++ = 'n';
			else if (text[i] == '\t') *out++ = 't';
			else if (text[i] == '\r') *out++ = 'r';
			else if (text[i] == '\\' || text[i] == '"') *out++ = text[i];
			else
			{
				*out++ = text[i];
				continue;
			}
			*out++ = '\\';
		}
		text.erase(std::remove_if(text.begin(), text.end(), [](uint64_t ch) { return ch < 0x20 || ch == 0x7f; }), text.end());
		return text;
	}

	template <typename C> struct UTF {};
	template <> struct UTF<wchar_t>
	{
		inline static std::wstring FromCodepoint(unsigned codepoint) { return { (wchar_t)codepoint }; } // TODO: surrogate pairs
	};

	template <typename C>
	struct Value : private std::variant<std::monostate, std::nullptr_t, bool, double, std::basic_string<C>, std::vector<Value<C>>, std::unordered_map<std::basic_string<C>, Value<C>>>
	{
		using std::variant<std::monostate, std::nullptr_t, bool, double, std::basic_string<C>, std::vector<Value<C>>, std::unordered_map<std::basic_string<C>, Value<C>>>::variant;

		explicit operator bool() const { return index(); }
		bool IsNull() const { return index() == 1; }
		auto Boolean() const { return std::get_if<bool>(this); }
		auto Number() const { return std::get_if<double>(this); }
		auto String() const { return std::get_if<std::basic_string<C>>(this); }
		auto Array() const { return std::get_if<std::vector<Value<C>>>(this); }
		auto Object() const { return std::get_if<std::unordered_map<std::basic_string<C>, Value<C>>>(this); }

		const Value<C>& operator[](std::basic_string<C> key) const
		{
			if (auto object = Object()) if (auto it = object->find(key); it != object->end()) return it->second;
			return failure;
		}
		const Value<C>& operator[](int i) const
		{
			if (auto array = Array()) if (i < array->size()) return array->at(i);
			return failure;
		}

		static const Value<C> failure;
	};
	template <typename C> const Value<C> Value<C>::failure;
	
	template <typename C, int maxDepth = 25>
	Value<C> Parse(const std::basic_string<C>& text, int64_t& i, int depth)
	{
		if (depth > maxDepth) return {};
		C ch;
		auto SkipWhitespace = [&]
		{
			while (i < text.size() && (text[i] == ' ' || text[i] == '\n' || text[i] == '\r' || text[i] == '\t')) ++i;
			if (i >= text.size()) return true;
			ch = text[i];
			return false;
		};
		auto ExtractString = [&]
		{
			std::basic_string<C> unescaped;
			i += 1;
			for (; i < text.size(); ++i)
			{
				auto ch = text[i];
				if (ch == '"') return i += 1, unescaped;
				if (ch == '\\')
				{
					ch = text[i + 1];
					if (ch == 'u' && isxdigit(text[i + 2]) && isxdigit(text[i + 3]) && isxdigit(text[i + 4]) && isxdigit(text[i + 5]))
					{
						char charCode[] = { text[i + 2], text[i + 3], text[i + 4], text[i + 5], 0 };
						unescaped += UTF<C>::FromCodepoint(strtoul(charCode, nullptr, 16));
						i += 5;
						continue;
					}
					for (auto [original, value] : Array<char, char>{ { 'b', '\b' }, {'f', '\f'}, {'n', '\n'}, {'r', '\r'}, {'t', '\t'} }) if (ch == original)
					{
						unescaped.push_back(value);
						goto replaced;
					}
					unescaped.push_back(ch);
					replaced: i += 1;
				}
				else unescaped.push_back(ch);
			}
			return unescaped;
		};

		if (SkipWhitespace()) return {};

		static C nullStr[] = { 'n', 'u', 'l', 'l' }, trueStr[] = { 't', 'r', 'u', 'e' }, falseStr[] = { 'f', 'a', 'l', 's', 'e' };
		if (ch == nullStr[0])
			if (std::char_traits<C>::compare(text.data() + i, nullStr, std::size(nullStr)) == 0) return i += std::size(nullStr), nullptr;
			else return {};
		if (ch == trueStr[0])
			if (std::char_traits<C>::compare(text.data() + i, trueStr, std::size(trueStr)) == 0) return i += std::size(trueStr), true;
			else return {};
		if (ch == falseStr[0])
			if (std::char_traits<C>::compare(text.data() + i, falseStr, std::size(falseStr)) == 0) return i += std::size(falseStr), false;
			else return {};

		if (ch == '-' || (ch >= '0' && ch <= '9'))
		{
			std::string number;
			for (; i < text.size() && ((text[i] >= '0' && text[i] <= '9') || text[i] == '-' || text[i] == '+' || text[i] == 'e' || text[i] == 'E' || text[i] == '.'); ++i)
				number.push_back(text[i]);
			return strtod(number.c_str(), NULL);
		}

		if (ch == '"') return ExtractString();

		if (ch == '[')
		{
			std::vector<Value<C>> array;
			while (true)
			{
				i += 1;
				if (SkipWhitespace()) return {};
				if (ch == ']') return i += 1, Value<C>(array);
				if (!array.emplace_back(Parse<C, maxDepth>(text, i, depth + 1))) return {};
				if (SkipWhitespace()) return {};
				if (ch == ']') return i += 1, Value<C>(array);
				if (ch != ',') return {};
			}
		}

		if (ch == '{')
		{
			std::unordered_map<std::basic_string<C>, Value<C>> object;
			while (true)
			{
				i += 1;
				if (SkipWhitespace()) return {};
				if (ch == '}') return i += 1, Value<C>(object);
				if (ch != '"') return {};
				auto key = ExtractString();
				if (SkipWhitespace() || ch != ':') return {};
				i += 1;
				if (!(object[std::move(key)] = Parse<C, maxDepth>(text, i, depth + 1))) return {};
				if (SkipWhitespace()) return {};
				if (ch == '}') return i += 1, Value<C>(object);
				if (ch != ',') return {};
			}
		}

		return {};
	}
	
	template <typename C>
	Value<C> Parse(const std::basic_string<C>& text)
	{
		int64_t start = 0;
		return Parse(text, start, 0);
	}
}

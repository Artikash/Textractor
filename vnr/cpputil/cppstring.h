#ifndef CPPSTRING_H
#define CPPSTRING_H

// cppstring.h
// 10/12/2014 jichi

#include <cstring>
#include <string>

// Initializers

template <typename charT, typename stringT>
inline std::basic_string<charT> cpp_basic_string_of(const stringT &s)
{ return std::basic_string<charT>(s.cbegin(), s.cend()); }

template <typename stringT>
inline std::string cpp_string_of(const stringT &s)
{ return std::string(s.cbegin(), s.cend()); }

inline std::string cpp_string_of(const char *s)
{ return s; }

inline std::string cpp_string_of(const wchar_t *s)
{ return std::string(s, s + ::wcslen(s)); }

template <typename stringT>
inline std::wstring cpp_wstring_of(const stringT &s)
{ return std::wstring(s.cbegin(), s.cend()); }

inline std::wstring cpp_wstring_of(const wchar_t *s)
{ return s; }

inline std::wstring cpp_wstring_of(const char *s)
{ return std::wstring(s, s + ::strlen(s)); }

#endif // CPPSTRING_H

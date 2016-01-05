#ifndef CPPSTRING_H
#define CPPSTRING_H

// cppstring.h
// 10/12/2014 jichi

/#include <string>

// Initializers

template <typename charT>
inline std::basic_string<charT> cpp_basic_string_of(const std::string &s)
{ return std::basic_string<charT>(s.begin(), s.end()); }

inline std::wstring cpp_wstring_of(const std::string &s)
{ return std::wstring(s.begin(), s.end()); }

#endif // CPPSTRING_H

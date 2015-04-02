#ifndef CPPUNICODE_H
#define CPPUNICODE_H

#include <string>
typedef std::basic_string<char16_t, std::char_traits<char16_t>, std::allocator<char16_t> > cpp_u16string;
typedef std::basic_string<char32_t, std::char_traits<char32_t>, std::allocator<char32_t> > cpp_u32string;

// <fstream>
#if defined(_FSTREAM_) || defined(_LIBCPP_FSTREAM) || defined(_GLIBCXX_FSTREAM)
typedef std::basic_ifstream<char16_t, std::char_traits<char16_t> > cpp_u16ifstream;
typedef std::basic_ifstream<char32_t, std::char_traits<char32_t> > cpp_u32ifstream;

typedef std::basic_ofstream<char16_t, std::char_traits<char16_t> > cpp_u16ofstream;
typedef std::basic_ofstream<char32_t, std::char_traits<char32_t> > cpp_u32ofstream;

typedef std::basic_fstream<char16_t, std::char_traits<char16_t> > cpp_u16fstream;
typedef std::basic_fstream<char32_t, std::char_traits<char32_t> > cpp_u32fstream;
#endif // <fstream>

inline char16_t cpp_u32low(char32_t c) { return c; }
inline char16_t cpp_u32high(char32_t c) { return c >> 16; }

#endif // CPPUNICODE_H

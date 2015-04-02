#ifndef CPPLOCALE_H
#define CPPLOCALE_H

// cpplocale.h
// 9/26/2014 jichi

#include <codecvt>
#include <locale>

//#include <boost/locale.hpp>

// See: http://stackoverflow.com/questions/20195262/how-to-read-an-utf-8-encoded-file-containing-chinese-characters-and-output-them
// The same as boost::locale::generator().generate("UTF-8"), which require linking
// See: http://en.cppreference.com/w/cpp/locale/codecvt_utf8
// - 0x10ffff is the default maximum value.
// - std::consume_header will skip the leading encoding byte from the input.
template <class charT>
inline std::locale cpp_utf8_locale(std::locale init = std::locale())
{ return std::locale(init, new std::codecvt_utf8<charT, 0x10ffff, std::consume_header>()); }

#endif // CPPLOCALE_H

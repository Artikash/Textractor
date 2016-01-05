#ifndef CPPLOCALE_H
#define CPPLOCALE_H

// cpplocale.h
// 9/26/2014 jichi

#include <locale>

#ifdef WITHOUT_CXX_CODECVT
// http://www.boost.org/doc/libs/1_48_0/libs/serialization/doc/codecvt.html
# define BOOST_UTF8_BEGIN_NAMESPACE
# define BOOST_UTF8_END_NAMESPACE
# define BOOST_UTF8_DECL
# include <boost/detail/utf8_codecvt_facet.hpp>
# include <boost/detail/utf8_codecvt_facet.ipp> // WARNING: This implementation should only be included ONCE
# define CPPLOCALE_NEW_FACET_UTF8(charT)    (new utf8_codecvt_facet) // charT is ignored and assumed to be wchar_t
//# include <boost/detail/serialization/utf8_codecvt_facet.hpp>
//# define CPPLOCALE_NEW_FACET_UTF8(charT)  (new utf8_codecvt_facet<charT>)
#else
# include <codecvt>
# define CPPLOCALE_NEW_FACET_UTF8(charT)    (new std::codecvt_utf8<charT, 0x10ffff, std::consume_header>)
#endif // WITHOUT_CXX_CODECVT

//#include <boost/locale.hpp>

// See: http://stackoverflow.com/questions/20195262/how-to-read-an-utf-8-encoded-file-containing-chinese-characters-and-output-them
// The same as boost::locale::generator().generate("UTF-8"), which require linking
// See: http://en.cppreference.com/w/cpp/locale/codecvt_utf8
// - 0x10ffff is the default maximum value.
// - std::consume_header will skip the leading encoding byte from the input.
template <class charT>
inline std::locale cpp_utf8_locale(std::locale init = std::locale()) //::empty())
{ return std::locale(init, CPPLOCALE_NEW_FACET_UTF8(charT)); }

#endif // CPPLOCALE_H

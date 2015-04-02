#ifndef CPPPATH_H
#define CPPPATH_H

// cpppath.h
// 5/7/2014 jichi

#include <cstddef> // for size_t

enum : char { cpp_pathsep_unix = '/' , cpp_pathsep_win = '\\' };

// basename

template <class charT>
inline const charT *cpp_basic_basename(const charT *s)
{
  const charT *p = s;
  //if (s) // not checked
  for (; *s; s++)
    if (*s == cpp_pathsep_unix || *s == cpp_pathsep_win)
      p = s + 1;
  return p;
}

//if (const char *r = ::strrchr(s, pathsep))
//  return r + 1; // skip the path seperator
//else
//  return s;
inline const char *cpp_basename(const char *s) { return cpp_basic_basename<char>(s); }

//if (const wchar_t *r = ::wcsrchr(s, pathsep))
//  return r + 1; // skip the path seperator
//else
//  return s;
inline const wchar_t *cpp_wbasename(const wchar_t *s) { return cpp_basic_basename<wchar_t>(s); }

// dirmame

///  Return the length so that s[len] == pathsep
template <class charT>
inline size_t cpp_basic_dirlen(const charT *s)
{
  const charT *p = s,
              *t = s;
  //if (s) // not checked
  for (; *s; s++)
    if (*s == cpp_pathsep_unix || *s == cpp_pathsep_win)
      p = s + 1;
  return p - t;
}

inline size_t cpp_wdirlen(const char *s) { return cpp_basic_dirlen<char>(s); }
inline size_t cpp_wdirlen(const wchar_t *s) { return cpp_basic_dirlen<wchar_t>(s); }

#endif // CPPPATH_H

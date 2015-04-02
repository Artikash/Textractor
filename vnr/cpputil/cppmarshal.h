#ifndef CPPMARSHAL_H
#define CPPMARSHAL_H

// cppmarshal.h
// 10/12/2014 jichi
//
// Functions are by default big-endian, the same as memory layout.
#include "cpputil/cppcstring.h"
#include "cpputil/cpptype.h"
#include <cstring>

/* Read */

// Read number

template <typename valT, typename byteT>
inline const byteT *cpp_marshal_getval(const byteT *p, valT *v)
{ *v = *reinterpret_cast<const valT *>(p); return p + sizeof(valT); }

// Read pointer

template <typename ptrT, typename byteT> \
inline const byteT *cpp_marshal_getptr(const byteT *p, ptrT v)
{ return cpp_marshal_getval<unsigned long>(p, reinterpret_cast<unsigned long *>(v)); }

// Read string

template <typename charT, typename byteT>
inline const byteT *cpp_marshal_getstr(const byteT *p, charT *s)
{
  size_t n = cpp_basic_strlen(p);
  ::memcpy(s, p, n + 1); // including '\0'
  return p + n + 1;
}

template <typename charT, typename byteT>
inline const byteT *cpp_marshal_getnstr(const byteT *p, charT *s, size_t n)
{
  if (n = cpp_basic_strnlen(p, n))
    ::memcpy(s, p, n); // including '\0'
  s[n] = 0;
  return p + n + 1;
}

/* Write */

// Write number

template <typename valT, typename byteT>
inline byteT *cpp_marshal_putval(byteT *p, valT v)
{ *reinterpret_cast<valT *>(p) = v; return p + sizeof(valT); }

// Write pointer

template <typename ptrT, typename byteT> \
inline byteT *cpp_marshal_putptr(byteT *p, ptrT v)
{ return cpp_marshal_putval<unsigned long>(p, reinterpret_cast<unsigned long>(v)); }

// Write string

template <typename charT, typename byteT>
inline byteT *cpp_marshal_putstr(byteT *p, charT *s)
{
  size_t n = cpp_basic_strlen(s);
  ::memcpy(p, s, n + 1); // including '\0'
  return p + n + 1;
}

template <typename charT, typename byteT>
inline byteT *cpp_marshal_putstr(byteT *p, charT *s, size_t n)
{
  if (n = cpp_basic_strnlen(s, n))
    ::memcpy(p, s, n); // including '\0'
  s[n] = 0;
  return p + n + 1;
}

/* Expansion */

#define CPP_DECLARE_MARSHAL_GETVAL(type) \
  template <typename byteT> \
  inline const byteT *cpp_marshal_get##type(const byteT *p, cpp_##type *v) { return cpp_marshal_getval(p, v); }

#define CPP_DECLARE_MARSHAL_PUTVAL(type) \
  template <typename byteT> \
  inline byteT *cpp_marshal_put##type(byteT *p, cpp_##type v) { return cpp_marshal_putval(p, v); }

CPP_DECLARE_MARSHAL_PUTVAL(float)
CPP_DECLARE_MARSHAL_PUTVAL(double)
CPP_DECLARE_MARSHAL_GETVAL(float)
CPP_DECLARE_MARSHAL_GETVAL(double)
CPP_DECLARE_MARSHAL_GETVAL(int)
CPP_DECLARE_MARSHAL_GETVAL(int8)
CPP_DECLARE_MARSHAL_GETVAL(int32)
CPP_DECLARE_MARSHAL_GETVAL(int64)
CPP_DECLARE_MARSHAL_GETVAL(uint)
CPP_DECLARE_MARSHAL_GETVAL(uint8)
CPP_DECLARE_MARSHAL_GETVAL(uint32)
CPP_DECLARE_MARSHAL_GETVAL(uint64)

CPP_DECLARE_MARSHAL_PUTVAL(int)
CPP_DECLARE_MARSHAL_PUTVAL(int8)
CPP_DECLARE_MARSHAL_PUTVAL(int32)
CPP_DECLARE_MARSHAL_PUTVAL(int64)
CPP_DECLARE_MARSHAL_PUTVAL(uint)
CPP_DECLARE_MARSHAL_PUTVAL(uint8)
CPP_DECLARE_MARSHAL_PUTVAL(uint32)
CPP_DECLARE_MARSHAL_PUTVAL(uint64)

#endif // CPPMARSHAL_H

#ifndef SKHASH_H
#define SKHASH_H

// skhash.h
// 8/1/2011

#include "sakurakit/skglobal.h"
#include <QtGlobal>

SK_BEGIN_NAMESPACE

enum : quint64 { djb2_hash0 = 5381 };

///  djb2: h = h*33 + c
inline quint64 djb2(const quint8 *str, quint64 hash = djb2_hash0)
{
  quint8 c;
  while ((c = *str++))
    hash = ((hash << 5) + hash) + c; // hash * 33 + c
  return hash;
}

/// s: signed char
inline quint64 djb2_s(const char *str, quint64 hash = djb2_hash0)
{
  char c;
  while ((c = *str++))
    hash = ((hash << 5) + hash) + c; // hash * 33 + c
  return hash;
}

///  n: length
inline quint64 djb2_n(const quint8 *str, size_t len, quint64 hash = djb2_hash0)
{
  while (len--)
    hash = ((hash << 5) + hash) + (*str++); // hash * 33 + c
  return hash;
}

///  sdbm: hash(i) = hash(i - 1) * 65599 + str[i];
inline quint64 sdbm(const quint8 *str, quint64 hash = 0)
{
  quint8 c;
  while ((c = *str++))
     hash = c + (hash << 6) + (hash << 16) - hash;
  return hash;
}

inline quint64 loselose(const quint8 *str, quint64 hash = 0)
{
  quint8 c;
  while ((c = *str++))
    hash += c;
  return hash;
}

SK_END_NAMESPACE

#endif // SKHASH_H

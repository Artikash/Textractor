#ifndef CPPMATH_H
#define CPPMATH_H

// cppmacro.h
// 10/12/2014 jichi
#include <cmath>

// The same as qMin
template <typename T>
inline const T &cpp_min(const T &a, const T &b) { return (a < b) ? a : b; }

// The same as qMax
template <typename T>
inline const T &cpp_max(const T &a, const T &b) { return (a < b) ? b : a; }

// The same as qBound
template <typename T>
inline const T &cpp_bound(const T &min, const T &val, const T &max)
{ return cpp_max(min, cpp_min(max, val)); }

// The same as qFuzzyCompare
inline bool cpp_fuzzy_compare(float p1, float p2)
{ return (abs(p1 - p2) <= 0.00001f * cpp_min(abs(p1), abs(p2))); }

#endif // CPPMATH_H

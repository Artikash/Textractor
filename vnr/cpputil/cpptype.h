#ifndef CPPTYPE_H
#define CPPTYPE_H

// cpptype.h
// 10/12/2014 jichi
#include <cstdint>

// Platform-dependent

typedef char cpp_char;
typedef unsigned char cpp_uchar;

typedef short cpp_short;
typedef unsigned short cpp_ushort;

typedef int cpp_int;
typedef unsigned int cpp_uint;

typedef long cpp_long;
typedef unsigned long cpp_ulong;

typedef long long cpp_llong;
typedef unsigned long long cpp_ullong;

typedef float cpp_float;
typedef double cpp_double;

// Platform-independent

typedef int8_t cpp_int8;
typedef uint8_t cpp_uint8;

typedef cpp_int8 cpp_byte;
typedef cpp_uint8 cpp_ubyte;

typedef int32_t cpp_int32;
typedef uint32_t cpp_uint32;

typedef int64_t cpp_int64;
typedef uint64_t cpp_uint64;

#endif // CPPTYPE_H

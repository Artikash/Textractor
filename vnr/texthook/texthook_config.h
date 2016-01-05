#pragma once

// texthook_config.h
// 10/20/2011 jichi

//#define TEXTHOOK_EXPORT

#ifndef TEXTHOOK_EXPORT
# ifdef TEXTHOOK_STATIC_LIB
#  define TEXTHOOK_EXPORT
# elif defined(TEXTHOOK_BUILD_LIB)
#  define TEXTHOOK_EXPORT Q_DECL_EXPORT
# else
#  define TEXTHOOK_EXPORT Q_DECL_IMPORT
# endif
#endif // TEXTHOOK_EXPORT

#define TEXTHOOK_DEFAULT_NAME   "H-code"

// EOF

#pragma once
// winapi_p.h
// 10/5/2012 jichi
// Internal header.
// Wrapper of <windows.h>

#ifndef WINAPI_BEGIN_NAMESPACE
# define WINAPI_BEGIN_NAMESPACE namespace winapi {
#endif
#ifndef WINAPI_END_NAMESPACE
# define WINAPI_END_NAMESPACE   } // namespace winapi
#endif

WINAPI_BEGIN_NAMESPACE
bool IsProcessActiveWithId(unsigned long dwProcessId);
WINAPI_END_NAMESPACE

// EOF

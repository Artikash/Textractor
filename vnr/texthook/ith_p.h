#pragma once

// ith_p.h
// 10/15/2011 jichi
// Internal header.
// Wrapper of functions from ITH.

#include <QtCore/QString>

struct HookParam; // opaque, declared in ITH/common.h

namespace Ith {

///  Parse hook code, and save the result to hook param if succeeded.
bool parseHookCode(_In_ const QString &code, _Out_ HookParam *hp, bool verbose = true);
bool verifyHookCode(_In_ const QString &code);

} // namespace Ith

// EOF

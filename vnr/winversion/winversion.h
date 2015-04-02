#pragma once

// winversion.h
// 9/5/2014 jichi

#ifdef _MSC_VER
# include <cstddef> // for wchar_t
#endif // _MSC_VER

namespace WinVersion {

bool queryFileVersion(const wchar_t *path, int ver[4]);

} // namespace WinVersion

// EOF

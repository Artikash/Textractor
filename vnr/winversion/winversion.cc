// winversion.cc
// 9/5/2014 jichi

#include "winversion/winversion.h"
#include <windows.h>

// http://stackoverflow.com/questions/940707/how-do-i-programatically-get-the-version-of-a-dll-or-exe-file
bool WinVersion::queryFileVersion(const wchar_t *path, int ver[])
{
  bool ok = false;
  // get the version info for the file requested
  if (DWORD dwSize = ::GetFileVersionInfoSizeW(path, nullptr)) {
    UINT len = 0;
    BYTE *buf = new BYTE[dwSize];
    VS_FIXEDFILEINFO *info = nullptr;
    ok = ::GetFileVersionInfoW(path, 0, dwSize, buf)
      && ::VerQueryValueW(buf, L"\\", (LPVOID*)&info, &len)
      && info;
    if (ok) {
      ver[0] = HIWORD(info->dwFileVersionMS),
      ver[1] = LOWORD(info->dwFileVersionMS),
      ver[2] = HIWORD(info->dwFileVersionLS),
      ver[3] = LOWORD(info->dwFileVersionLS);
    }
    delete[] buf;
  }
  return ok;
}

// EOF

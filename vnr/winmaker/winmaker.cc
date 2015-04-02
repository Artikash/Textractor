// winmaker.cc
// 2/1/2013 jichi

#include "winmaker/winmaker.h"
#include <windows.h>
//#include <commctrl.h>

#ifdef _MSC_VER
# pragma warning (disable:4800)   // C4800: forcing value to bool
#endif // _MSC_VER

// See: http://www.codeguru.com/cpp/w-p/dll/tips/article.php/c3635/Tip-Detecting-a-HMODULEHINSTANCE-Handle-Within-the-Module-Youre-Running-In.htm
extern "C" IMAGE_DOS_HEADER __ImageBase;
namespace { // unnamed
  inline HMODULE _get_module() { return reinterpret_cast<HMODULE>(&__ImageBase); }
} // unnamed

bool wm_register_hidden_class(LPCWSTR className)
{
  WNDCLASSEX wx = {};
  wx.cbSize = sizeof(wx);
  wx.lpfnWndProc = ::DefWindowProc;
  wx.hInstance = ::GetModuleHandle(nullptr);
  wx.lpszClassName = className;
  return ::RegisterClassEx(&wx);
}

wm_window_t wm_create_hidden_window(LPCWSTR windowName, LPCWSTR className, wm_module_t dllHandle)
{
  //return ::CreateWindowExA(0, className, windowName, 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, dllHandle, nullptr);
  HINSTANCE module = reinterpret_cast<HINSTANCE>(dllHandle);
  if (!module)
    module = _get_module();
  return ::CreateWindowEx(0, className, windowName, 0, 0, 0, 0, 0, 0, NULL, module, NULL);
}

bool wm_destroy_window(wm_window_t hwnd)
{ return ::DestroyWindow(reinterpret_cast<HWND>(hwnd)); }


// EOF
//
//void wm_init() { ::InitCommonControls(); }
//void wm_destroy() {}
//bool wm_destroy_window() { return ::DestroyWindow(hwnd); }


#pragma once

// winmaker.h
// 2/1/2013 jichi

#include <windows.h>
typedef void *wm_window_t; // HWMD
typedef void *wm_module_t; // HMODULE

bool wm_register_hidden_class(LPCWSTR className = L"hidden_class");

wm_window_t wm_create_hidden_window(
    LPCWSTR windowName = L"hidden_window",
    LPCWSTR className = L"Button", // bust be one of the common control widgets
    wm_module_t dllHandle  = nullptr);

bool wm_destroy_window(wm_window_t hwnd);

// EOF

//#ifdef QT_CORE_LIB
//#include <QtGui/qwindowdefs.h>
//WId wm_create_hidden_window(const char *className = "Button", const char *windowName = "hidden_window");

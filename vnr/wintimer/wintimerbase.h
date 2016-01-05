#pragma once

// wintimerbase.h
// 6/6/2012 jichi
//
// Internal header for wintimer base class.

#include "sakurakit/skglobal.h"
#include <functional>

#ifdef QT_CORE_LIB
# include <QtGui/qwindowdefs.h>
#else
# include <windows.h>
#endif // QT_CORE_LIB

#ifndef WINTIMER_BEGIN_NAMESPACE
# define WINTIMER_BEGIN_NAMESPACE
#endif
#ifndef WINTIMER_END_NAMESPACE
# define WINTIMER_END_NAMESPACE
#endif

WINTIMER_BEGIN_NAMESPACE

///  Internal base class for WinTimer
class WinTimerBase
{
  SK_CLASS(WinTimerBase)
  SK_DISABLE_COPY(WinTimerBase)

  // - Types -
public:
  typedef std::function<void ()> function_type;
#ifndef QT_CORE_LIB
  typedef HWND WId;
#endif // QT_CORE_LIB

  // - Methods -
public:
  ///  Construct a timer with the parent window handle.
  WinTimerBase()
    : parentWindow(0), // use 0 instead of nullptr to be consistent with Qt5
      interval(0), singleShot(false), active(false) {}

  bool isSingleShot() const { return singleShot; }
  bool isActive() const { return active; }

  ///  Start TimerProc
  void start();
  ///  Stop TimerProc
  void stop();
  ///  Invoke the callback. This function is the callback of the underlying TimerProc
  void trigger() { function(); }

  // - Fields -
protected:
  static WId globalWindow;

  WId parentWindow;
  int interval;
  bool singleShot;
  bool active;
  function_type function;

};

WINTIMER_END_NAMESPACE

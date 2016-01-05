#pragma once

// wintimer.h
// 6/6/2012 jichi
//
// A light-weighted native windows timer as a replacement of QTimer from Qt.
// Implementation is based on Windows Messaging. A visible parent hwnd is required.
//
// This timer is critical where QTimer or event loop are not available, or need to
// warp to different event loop. Some usage cases follow:
// - Used by texthook as a replacement of QTimer in non-QThread
// - Used by qapplicationloader to implement pseudo event loop
// - Used by winhook to synchronize with window event loop across threads

#include "wintimer/wintimerbase.h"
#include <boost/bind.hpp>

/**
 *  @brief  A light-weighted native windows timer as a replacement of QTimer.
 *
 *  Needed when in a thread where event loop is not accessible.
 *  Implemented using extensive inlining over pimp, so that the entire class
 *  could be put on the stack without heap.
 *
 *  Each timer requires an valid visible window's handle to synchronize with.
 *  Either specify the window handle with the parent window or a global window.
 */
class WinTimer : protected WinTimerBase
{
  SK_EXTEND_CLASS(WinTimer, WinTimerBase)
  SK_DISABLE_COPY(WinTimer)

  // - Construction -
public:
  //typedef std::function<void ()> function_type;
  using Base::function_type; ///< std::function<void ()>

  ///  Default parent window of all timers.
  static WId globalWindow() { return Base::globalWindow; }
  static void setGlobalWindow(WId winId) { Base::globalWindow = winId; }

  //static WId createHiddenWindow();

public:
  ///  Construct a timer with the parent window handle.
  explicit WinTimer(WId parentWindow = 0) { setParentWindow(parentWindow); }

  static void singleShot(int msecs, const function_type &f, WId parent = 0);

  // - Properties -
public:
  using Base::isActive;
  using Base::isSingleShot;

  void setSingleShot(bool t) { Base::singleShot = t; }

  //bool isEmpty() const { return Base::function.empty(); }

  WId parentWindow() const { return Base::parentWindow; }
  void setParentWindow(WId winId) { Base::parentWindow = winId ? winId : Base::globalWindow; }

  int interval() const { return Base::interval; }
  void setInterval(int msecs) { Base::interval = msecs; }

  ///  Timeout callback when trigger.
  void setFunction(const function_type &f) { Base::function = f; }

  ///  @overload  Set callback to a class method
  template <typename Class, typename Member>
    void setMethod(Class *obj, Member mfunc)
    { setFunction(boost::bind(mfunc, obj)); }

  ///  @overload  Set callback to a const class method
  template <typename Class, typename Member>
    void setMethod(const Class *obj, Member mfunc)
    { setFunction(boost::bind(mfunc, obj)); }

  // - Actions -
public:
  ///  Start TimerProc
  using Base::start;

  ///  Stop TimerProc
  using Base::stop;

  ///  Reset interval and start TimerProc
  void start(int interval)  { setInterval(interval); start(); }

  ///  Invoke the callback. This function is the callback of the underlying TimerProc
  using Base::trigger;
};

WINTIMER_END_NAMESPACE

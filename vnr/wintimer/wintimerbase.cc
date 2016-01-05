// wintimerbase.cc
// 6/6/2012 jichi

#include "wintimer/wintimerbase.h"
#ifdef QT_CORE_LIB
# include <qt_windows.h>
#else
# include <windows.h>
#endif // QT_CORE_LIB
#include "ccutil/ccmacro.h"

//#define DEBUG "wintimerbase.cc"
#include "sakurakit/skdebug.h"

static VOID CALLBACK WinTimerProc(
  HWND hwnd,         // ウィンドウのハンドル
  UINT uMsg,         // WM_TIMER メッセージ
  UINT_PTR idEvent,  // Timer ID
  DWORD dwTime       // 現在のシステム時刻
)
{
  Q_UNUSED(hwnd)
  Q_UNUSED(dwTime)
  Q_UNUSED(uMsg)
  Q_ASSERT(idEvent);
  if (CC_UNLIKELY(!idEvent))
    return;
  DOUT("enter");
  WinTimerBase *t = reinterpret_cast<WinTimerBase *>(idEvent);

  if (t->isSingleShot() && t->isActive())
    t->stop();
  t->trigger();
  DOUT("leave");
}

WINTIMER_BEGIN_NAMESPACE

// - Construction -

WId WinTimerBase::globalWindow;

//WId WinTimer::createHiddenWindow()
//{
//  DOUT("enter: warning: hidden window used");
//  QWidget *w = new QWidget;
//  w->resize(QSize());
//  w->show();
//  DOUT("leave");
//  return w->winId();
//}

// - Timer -

void WinTimerBase::start()
{
  DOUT("enter: active =" << active << ", interval =" << interval);
  active = true;
  ::SetTimer(parentWindow, reinterpret_cast<UINT_PTR>(this), interval, WinTimerProc);
  DOUT("leave");
}

void WinTimerBase::stop()
{
  DOUT("enter: active =" << active);
  active = false;
  ::KillTimer(parentWindow, reinterpret_cast<UINT_PTR>(this));
  DOUT("leave");
}

WINTIMER_END_NAMESPACE

// EOF

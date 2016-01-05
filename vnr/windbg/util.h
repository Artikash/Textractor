#pragma once

// windbg/util.h
// 1/27/2013 jichi

#include "windbg/windbg.h"
#include "sakurakit/skglobal.h"

#include <windows.h>

WINDBG_BEGIN_NAMESPACE

class ThreadsSuspenderPrivate;
/**
 *  When created, automatically suspends all threads in the current process.
 *  When destroyed, resume suspended threads.
 */
class ThreadsSuspender
{
  SK_CLASS(ThreadsSuspender)
  SK_DISABLE_COPY(ThreadsSuspender)
  SK_DECLARE_PRIVATE(ThreadsSuspenderPrivate)

public:
  explicit ThreadsSuspender(bool autoSuspend = true);
  ~ThreadsSuspender();

  void resume(); ///<  Manually resume all threads
  void suspend(); ///<  Manually suspend all threads
};

WINDBG_END_NAMESPACE

// EOF

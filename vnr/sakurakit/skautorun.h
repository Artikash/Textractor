#ifndef SKAUTORUN_H
#define SKAUTORUN_H

// skautorun.h
// 9/30/2012 jichi

#include "sakurakit/skglobal.h"
#include <functional>

SK_BEGIN_NAMESPACE

class SkAutoRun
{
public:
  typedef std::function<void ()> function_type;
  SkAutoRun(const function_type &start, const function_type &exit)
    : exit_(exit) { start(); }
  ~SkAutoRun() { exit_(); }
private:
  function_type exit_;
};

class SkAutoRunAtStartup
{
public:
  typedef SkAutoRun::function_type function_type;
  explicit SkAutoRunAtStartup(const function_type &start) { start(); }
};

class SkAutoRunAtExit
{
public:
  typedef SkAutoRun::function_type function_type;
  explicit SkAutoRunAtExit(const function_type &exit) : exit_(exit) {}
  ~SkAutoRunAtExit() { exit_(); }
private:
  function_type exit_;
};

SK_END_NAMESPACE

#endif // SkAUTORUN_H

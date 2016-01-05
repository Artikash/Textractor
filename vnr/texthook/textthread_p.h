#pragma once

// textthread_p.h
// 6/6/2012 jichi
// Internal header.
// Defines TextHook delegate class.

#include "sakurakit/skglobal.h"
#include <QtGui/qwindowdefs.h>

//QT_FORWARD_DECLARE_CLASS(QByteArray)

class SharedRef
{
  SK_CLASS(SharedRef)
  int count_;
public:
  SharedRef(): count_(1) {}
  int retainCount() const { return count_; }
  void retain() { count_++; }
  //void release() { count_--; }
  static void release(Self *x) { if (--x->count_ <= 0) delete x; }
};

// FIXME: This class is not thread-safe!
class TextThread;
class TextThreadDelegatePrivate;
class TextThreadDelegate : public SharedRef
{
  SK_EXTEND_CLASS(TextThreadDelegate, SharedRef)
  SK_DISABLE_COPY(TextThreadDelegate)
  SK_DECLARE_PRIVATE(TextThreadDelegatePrivate)
public:
  explicit TextThreadDelegate(TextThread *t);
  ~TextThreadDelegate();

  bool delegateOf(const Self *t) const;

  // - Properties -

  //TextThread *t() const;
  int threadNumber() const;
  qint32 signature() const;
  QString name() const;
  bool nameEquals(const char *that) const; // optimized

  // Maximum text size
  static int capacity();
  static void setCapacity(int value);

  static bool wideCharacter();
  static void setWideCharacter(bool value);

  static bool removesRepeat();
  static void setRemovesRepeat(bool value);

  static bool keepsSpace();
  static void setKeepsSpace(bool value);

  //TextThread *t() const;

  //int interval() const;
  void setInterval(int msecs);

  //WId parentWindow() const;
  void setParentWindow(WId winId);

  // - Actions -

  //void append(const QByteArray &data);
  /** Add data to the text thread
   *  @param  data  raw data
   *  @param  len  length of the data
   *  @param  space  Whether have LEADING space
   */
  void append(const char *data, int len, bool space=false);
  void flush();
  void touch(); // keep timer running
};

// EOF

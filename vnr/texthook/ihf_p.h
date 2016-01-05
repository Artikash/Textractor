#pragma once

// ihf_p.h
// 10/15/2011 jichi
// Internal header.
// Wrapper of IHF functions.

#include <QtCore/QHash>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtGui/qwindowdefs.h> // for WId

//struct Settings; // opaque in ith/host/settings.h
class HookManager; // opaque in ith/host/hookman.h
class TextThread; // opaque in ith/host/textthread.h
class TextThreadDelegate;

enum { ITH_THREAD_NAME_CAPACITY = 0x200 }; // used internally by ITH

class Ihf
{
  Ihf() {} // Singleton

  static bool enabled_;

  //static Settings *settings_;
  static HookManager *hookManager_;
  static qint64 messageInterval_;
  static WId parentWindow_;

  static QHash<TextThread *, TextThreadDelegate *> threadDelegates_;
  //static QHash<TextThreadDelegate *, TextThreadDelegate *> linkedDelegates_;
  static QHash<QString, ulong> hookAddresses_;

  enum { WhitelistSize = 0x20 + 1 }; // ITH capacity is 0x20
  static qint32 whitelist_[WhitelistSize]; // List of signatures. The last element is zero. I.e., at most BlackSize-1 threads.
  static bool whitelistEnabled_;
  static char keptThreadName_[ITH_THREAD_NAME_CAPACITY];
  //static QString userDefinedThreadName_;

public:

  // - Initialization -
  static void init();
  static void destroy();

  static bool load();
  static bool isLoaded() { return hookManager_; }
  static void unload();

  // - Properties -

  static bool isEnabled() { return enabled_; }
  static void setEnabled(bool t) { enabled_ = t; }

  ///  A valid window handle is required to make ITH work
  static WId parentWindow() { return parentWindow_; }
  static void setParentWindow(WId hwnd) { parentWindow_ = hwnd; }

  ///  Timeout (msecs) for a text message
  static qint64 messageInterval() { return messageInterval_; }
  static void setMessageInterval(qint64 msecs) { messageInterval_ = msecs; }

  // - Injection -
  static bool attachProcess(ulong pid);
  static bool detachProcess(ulong pid);
  static bool hijackProcess(ulong pid);

  ///  Add hook code
  static bool addHook(ulong pid, const QString &code, const QString &name = QString(), bool verbose = true);
  static bool updateHook(ulong pid, const QString &code); // not used
  static bool removeHook(ulong pid, const QString &code);
  static bool verifyHookCode(const QString &code);

  // - Whitelist -
  static bool isWhitelistEnabled() { return whitelistEnabled_; }
  static void setWhitelistEnabled(bool t) { whitelistEnabled_ = t; }

  static QList<qint32> whitelist();
  static void setWhitelist(const QList<qint32> &l);
  static void clearWhitelist();

  //static QString userDefinedThreadName() { return userDefinedThreadName_; }
  //static void setUserDefinedThreadName(const QString &val) { userDefinedThreadName_ = val; }
  static const char *keptThreadName() { return keptThreadName_;  }

  static void setKeptThreadName(const QString &v)
  {
    if (v.size() < ITH_THREAD_NAME_CAPACITY)
      ::strcpy(keptThreadName_, v.toAscii());
    else
      setKeptThreadName(v.left(ITH_THREAD_NAME_CAPACITY - 1));
  }

private:
  static bool whitelistContains(qint32 signature);

  // - Callbacks -
  //static ulong processAttach(ulong pid);
  //static ulong processDetach(ulong pid);
  //static ulong processNewHook(ulong pid);

  static ulong threadCreate(_In_ TextThread *t);
  static ulong threadRemove(_In_ TextThread *t);
  static ulong threadOutput(_In_ TextThread *t, _In_ uchar *data, _In_ ulong dataLength, _In_ ulong bNewLine, _In_ void *pUserData, _In_ bool space);
  //static ulong threadFilter(_In_ TextThread *t, _Out_ uchar *data, _In_ ulong dataLength, _In_ ulong bNewLine, _In_ void *pUserData);
  //static ulong threadReset(TextThread *t);
  //static void consoleOutput(const char *text);
  //static void consoleOutputW(const wchar_t *text);

  // - Linked threasds -
private:
  //static TextThreadDelegate *findLinkedDelegate(TextThreadDelegate *d);
  static void updateLinkedDelegate(TextThreadDelegate *d);
};

// EOF

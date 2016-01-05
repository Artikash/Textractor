#pragma once

// texthook.h
// 10/14/2011 jichi

#include "texthook_config.h"
#include "sakurakit/skglobal.h"
#include <QtCore/QByteArray>
#include <QtCore/QObject>
#include <QtCore/QList>
#include <QtCore/QString>
#include <QtGui/qwindowdefs.h> // for WId

class TextHookPrivate;
///  Singleton class. Only one instance is allowed.
class TEXTHOOK_EXPORT TextHook : public QObject
{
  Q_OBJECT
  Q_DISABLE_COPY(TextHook)
  SK_EXTEND_CLASS(TextHook, QObject)
  SK_DECLARE_PRIVATE(TextHookPrivate)

  // - Construction -
public:
  explicit TextHook(QObject *parent = nullptr);
  ~TextHook();

signals:
  void dataReceived(QByteArray raw, QByteArray rendered, qint32 signature, QString source);
  void processAttached(qint64 pid);
  void processDetached(qint64 pid);

  // - Properties -
public:
  ///  Limited by ITH
  int capacity() const;

  bool isEnabled() const;
  void setEnabled(bool t);

  WId parentWinId() const; ///< Must be set to a valid window so that ::SetTimer works
  void setParentWinId(WId hwnd);

  int interval() const; ///< Time to differentiate sentences
  void setInterval(int msecs);

  int dataCapacity() const; ///< Maximum text length
  void setDataCapacity(int value);

  bool removesRepeat() const;
  void setRemovesRepeat(bool value);

  bool keepsSpace() const;
  void setKeepsSpace(bool value);

  bool wideCharacter() const;
  void setWideCharacter(bool value);

  QString defaultHookName() const; ///< The default one is "H-code"
  void setDefaultHookName(const QString &name);

  bool isActive() const;
  void start();
  void stop();
  void clear();

  // - Injection -
public:
  //bool attachOneProcess(ulong pid, bool checkActive = false);
  bool attachProcess(ulong pid, bool checkActive = false);
  bool detachProcess(ulong pid, bool checkActive = false);
  bool hijackProcess(ulong pid);
  //void detachAllProcesses();
  //QList<ulong> attachedProcesses(bool checkActive = false) const;
  //ulong anyAttachedProcess(bool checkActive = false) const;
  //ulong currentProccess() const;

  bool containsProcess(ulong pid) const;
  bool isEmpty() const; ///<  Return true if at least one process is attached

  bool addHookCode(ulong pid, const QString &code, const QString &name = QString(), bool verbose = true);
  static bool verifyHookCode(const QString &code); ///< Return if hcode is valid
  //bool containsHook(ulong pid) const;
  //bool containsHook(ulong pid, const QString &code) const;
  //QString processHook(ulong pid) const;
  //QString currentHook() const { return processHook(currentProccess()); }
  bool removeHookCode(ulong pid); ///< Assume atmost one hcode per process

  // - Whitelist -
public:
  bool isThreadWhitelistEnabled() const;
  void setThreadWhitelistEnabled(bool t);
  QList<qint32> threadWhitelist() const;
  void setThreadWhitelist(const QList<qint32> &signatures);
  void clearThreadWhitelist();
  // Note: len(v) must be smaller than 0x200
  void setKeptThreadName(const QString &v);
  QString keptThreadName() const;
};

// EOF

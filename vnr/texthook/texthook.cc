// texthook.cc
// 10/14/2011 jichi

#include "texthook/texthook.h"
#include "texthook/texthook_p.h"
#include "texthook/ihf_p.h"
#include "texthook/textthread_p.h"
#include "texthook/winapi_p.h"
#include <QtCore>

//#define DEBUG "texthook.cc"
#include "sakurakit/skdebug.h"

//#include <ITH/IHF_SYS.h>
//namespace { int _ = IthInitSystemService(); }

/** Private class */

TextHookPrivate *TextHookPrivate::instance_;

/** Public class */

// - Construction -

//TextHook *TextHook::g_;
//TextHook *TextHook::globalInstance() { static Self g; return &g; }

//TextHook::TextHook(QObject *parent)
//  : Base(parent), d_(new D)
//{}

TextHook::TextHook(QObject *parent)
  : Base(parent), d_(new D(this))
{
  Ihf::init();
  //Ihf::setUserDefinedThreadName(d_->source);
  DOUT("pass");
}

TextHook::~TextHook()
{
  DOUT("enter");
  if (isActive())
    stop();
  delete d_;

  Ihf::destroy();
  DOUT("leave");
}

// - Properties -

int TextHook::dataCapacity() const
{ return TextThreadDelegate::capacity(); }

void TextHook::setDataCapacity(int value)
{ TextThreadDelegate::setCapacity(value); }

bool TextHook::removesRepeat() const
{ return TextThreadDelegate::removesRepeat(); }

void TextHook::setRemovesRepeat(bool value)
{ TextThreadDelegate::setRemovesRepeat(value); }

bool TextHook::keepsSpace() const
{ return TextThreadDelegate::keepsSpace(); }

void TextHook::setKeepsSpace(bool value)
{ TextThreadDelegate::setKeepsSpace(value); }

bool TextHook::wideCharacter() const
{ return TextThreadDelegate::wideCharacter(); }

void TextHook::setWideCharacter(bool value)
{ TextThreadDelegate::setWideCharacter(value); }

// see: ITH/common.h
int TextHook::capacity() const
{ return 0x20; }

QString TextHook::defaultHookName() const
{ return d_->source; }

void TextHook::setDefaultHookName(const QString &name)
{
  d_->source = name;
  //Ihf::setUserDefinedThreadName(name);
}

bool TextHook::isEnabled() const
{ return d_->enabled; }

void TextHook::setEnabled(bool t)
{
  d_->enabled = t;
  Ihf::setEnabled(t);
}

bool TextHook::isActive() const
{ return Ihf::isLoaded(); }

void TextHook::start()
{ Ihf::load(); }

void TextHook::stop()
{
  if (!isEmpty())
    clear();
  Ihf::unload();
}

WId TextHook::parentWinId() const { return Ihf::parentWindow(); }
void TextHook::setParentWinId(WId hwnd) { Ihf::setParentWindow(hwnd); }

int TextHook::interval() const
{ return Ihf::messageInterval(); }

void TextHook::setInterval(int msecs)
{ Ihf::setMessageInterval(msecs); }

// - Injection -

void TextHook::clear()
{
  DOUT("enter");
  foreach (ulong pid, d_->pids)
    detachProcess(pid);
  if (!d_->hooks.isEmpty())
    d_->hooks.clear();
  clearThreadWhitelist();
  DOUT("leave");
}

bool TextHook::containsProcess(ulong pid) const { return d_->pids.contains(pid); }
bool TextHook::isEmpty() const { return d_->pids.isEmpty(); }

//QList<ulong> TextHook::attachedProcesses(bool checkActive) const
//{
//  if (isEmpty() || !checkActive)
//    return d_->pids;
//
//  QList<ulong> ret;
//  foreach (ulong pid, d_->pids)
//    if (winapi::IsProcessActiveWithId(pid))
//      ret.append(pid);
//  return ret;
//}

//ulong TextHook::currentProccess() const
//{ return anyAttachedProcess(true); } // check active = true

//ulong TextHook::anyAttachedProcess(bool checkActive) const
//{
//  if (isEmpty())
//    return 0;
// if (!checkActive)
//   return d_->pids.first();
//
//  foreach (ulong pid, d_->pids)
//    if (winapi::IsProcessActiveWithId(pid))
//      return pid;
//  return 0;
//}

//bool TextHook::attachOneProcess(ulong pid, bool checkActive)
//{
//  DOUT("enter: pid =" << pid);
//  DOUT("isAttached =" << containsProcess(pid));
//  if (!isActive())
//    start();
//
//  if (checkActive && !winapi::IsProcessActiveWithId(pid)) {
//    DOUT("leave: ret = false, isActive = false");
//    return false;
//  }
//
//  if (containsProcess(pid)) {
//    DOUT("leave: pid already attached");
//    return true;
//  }
//
//  detachAllProcesses();
//
//  bool ret = Ihf::attachProcess(pid);
//  if (ret && !containsProcess(pid)) {
//    d_->pids.removeAll(pid);
//    d_->pids.append(pid);
//    emit processAttached(pid);
//  }
//
//  DOUT("leave: ret =" << ret);
//  return ret;
//}

bool TextHook::attachProcess(ulong pid, bool checkActive)
{
  DOUT("enter: pid =" << pid << ", isAttached =" << containsProcess(pid));
  if (!isActive())
    start();
  Q_ASSERT(isActive());
  DOUT("isActive =" << isActive());

  if (checkActive && !winapi::IsProcessActiveWithId(pid)) {
    DOUT("leave: ret = false, isActive = false");
    return false;
  }

  bool ret = Ihf::attachProcess(pid);
  if (ret) {
    d_->pids.insert(pid);
    emit processAttached(pid);
  }

  DOUT("leave: ret =" << ret);
  return ret;
}

bool TextHook::detachProcess(ulong pid, bool checkActive)
{
  DOUT("enter: pid =" << pid << ", isAttached =" << containsProcess(pid));
  Q_ASSERT(isActive());

  auto it = d_->pids.find(pid);
  if (it == d_->pids.end()) {
    DOUT("leave: ret = false, not attached");
    return false;
  }
  d_->pids.erase(it);
  d_->hooks.remove(pid);

  if (checkActive && !winapi::IsProcessActiveWithId(pid)) {
    emit processDetached(pid);
    DOUT("leave: ret = false, isActive = false");
    return false;
  }

  bool ret = Ihf::detachProcess(pid);
  //try {
  //  ret = Ihf::detachProcess(pid);
  //} catch (...) {
  //  DOUT("warning: detach exception");
  //}

  emit processDetached(pid);
  DOUT("leave: ret =" << ret);
  return ret;
}

bool TextHook::hijackProcess(ulong pid)
{
  DOUT("enter: pid =" << pid);
  Q_ASSERT(isActive());

  if (!containsProcess(pid)) {
    DOUT("leave: aborted, process not attached");
    return false;
  }

  // 7/12/2015: Function disabled
  return true;

  //bool ret = Ihf::hijackProcess(pid);
  //DOUT("leave: ret =" << ret);
  //return ret;
}

//void TextHook::detachAllProcesses()
//{
//  DOUT("enter");
//  foreach (ulong pid, d_->pids)
//    detachProcess(pid);
//  if (!d_->hooks.isEmpty())
//    d_->hooks.clear();
//  DOUT("leave");
//}

// - Hook -

//bool TextHook::containsHook(ulong pid) const
//{ return d_->hooks.contains(pid); }
//
//bool TextHook::containsHook(ulong pid, const QString &code) const
//{ return processHook(pid) == code; }

bool TextHook::addHookCode(ulong pid, const QString &code, const QString &name, bool verbose)
{
  DOUT("enter: pid =" << pid << ", code =" << code);
  if (isEmpty() || !containsProcess(pid)) {
    DOUT("leave: failed, process not attached");
    return false;
  }
  if (d_->hooks.contains(pid)) {
    DOUT("leave: failed, hook already exists");
    return false;
  }
  bool ok = Ihf::addHook(pid, code,
                         name.isEmpty() ? defaultHookName() : name,
                         verbose);
  if (ok)
    d_->hooks[pid] = code;
  DOUT("leave: ret =" << ok);
  return ok;
}

bool TextHook::verifyHookCode(const QString &code) { return Ihf::verifyHookCode(code); }

bool TextHook::removeHookCode(ulong pid)
{
  DOUT("enter");
  auto p = d_->hooks.find(pid);
  if (p == d_->hooks.end()) {
    DOUT("leave: not hooked");
    return false;
  }

  //DOUT("remove existing hook, THIS SHOULD NOT HAPPEN");
  bool ok = Ihf::removeHook(pid, p.value());
  d_->hooks.erase(p);
  DOUT("leave: ret =" << ok);
  return ok;
}

//QString TextHook::processHook(ulong pid) const
//{
//  auto p = d_->hooks.find(pid);
//  return p == d_->hooks.end() ? QString() : p.value();
//}

bool TextHook::isThreadWhitelistEnabled() const { return Ihf::isWhitelistEnabled(); }

void TextHook::setThreadWhitelistEnabled(bool t) { Ihf::setWhitelistEnabled(t); }

QList<qint32> TextHook::threadWhitelist() const { return Ihf::whitelist(); }

void TextHook::setThreadWhitelist(const QList<qint32> &sigs) { Ihf::setWhitelist(sigs); }

void TextHook::clearThreadWhitelist() { Ihf::clearWhitelist(); }

QString TextHook::keptThreadName() const { return Ihf::keptThreadName(); }

void TextHook::setKeptThreadName(const QString &v) { Ihf::setKeptThreadName(v); }

// EOF

/*
QString
TextHook::guessEncodingForFile(const QString &fileName)
{
  static QHash<QString, QString> db;
  if (db.isEmpty()) {
    db["malie.exe"] = "UTF-16";
  }
  auto p = db.find(fileName);
  return p == db.end() ? QString() : p.value();
}

// - Helpers -

bool
TextHook::isStandardHookName(const QString &name) const
{
  static QSet<uint> hashes;
  if (hashes.isEmpty()) {
#define ADD(_text)  hashes.insert(qHash(QString(_text)))
    ADD("ConsoleOutput");
    ADD("GetTextExtentPoint32A");
    ADD("GetGlyphOutlineA");
    ADD("ExtTextOutA");
    ADD("TextOutA");
    ADD("GetCharABCWidthsA");
    ADD("DrawTextA");
    ADD("DrawTextExA");
    ADD("GetTextExtentPoint32W");
    ADD("GetGlyphOutlineW");
    ADD("ExtTextOutW");
    ADD("TextOutW");
    ADD("GetCharABCWidthsW");
    ADD("DrawTextW");
    ADD("DrawTextExW");
#undef ADD
  }
  uint h = qHash(name);
  return hashes.contains(h);
}

bool
TextHook::isKnownHookForProcess(const QString &hook, const QString &proc) const
{
  // TODO: update database on line periodically
  qDebug() << "qth::isKnownHookForProcess: hook ="  << hook << ", proc =" << proc;

  static QSet<uint> hashes;
  if (hashes.isEmpty()) {
#define ADD(_hook, _proc)  hashes.insert(qHash(QString(_hook) + "\n" + _proc))
    //ADD("Malie", "malie"); // light
    ADD("GetGlyphOutlineA", "STEINSGATE");
    ADD("StuffScriptEngine", "EVOLIMIT");
#undef ADD
  }
  uint h = qHash(hook + "\n" + proc);
  return hashes.contains(h);
}

QString
TextHook::hookNameById(ulong hookId) const
{
  //return Ihf::getHookNameById(hookId);
  // FIXME: supposed to be the engine name, unimplemented
  Q_UNUSED(hookId)
  return QString();
}


*/

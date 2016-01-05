// Host_p.cc
// 10/15/2011 jichi

#include "texthook/ihf_p.h"
#include "texthook/ith_p.h"
#include "texthook/textthread_p.h"
#include "host/host.h"
#include "vnrhook/include/types.h"
#include "ithsys/ithsys.h"
#include "wintimer/wintimer.h"
#include <QtCore/QDebug>

#ifdef WITH_LIB_WINMAKER
# include "winmaker/winmaker.h"
#endif // WITH_LIB_WINMAKER

//#define ITH_RUNNING_EVENT L"ITH_PIPE_EXIST"
//#define ITH_RUNNING_MUTEX L"ITH_RUNNING"
//#define ITH_MUTEX_NAME  L"ITH_MAIN_RUNNING"

//#define DEBUG "ihf_p.cc"
#include "sakurakit/skdebug.h"

//#define ITH_WITH_LINK

// - Construction -

//bool Ihf::debug_ = true;
bool Ihf::enabled_ = true;

//Settings *Ihf::settings_;
HookManager *Ihf::hookManager_;
qint64 Ihf::messageInterval_ = 250; // 0.25 secs by default, larger than the split_time (0.2sec) in ITH::setman
WId Ihf::parentWindow_;

QHash<TextThread *, TextThreadDelegate *> Ihf::threadDelegates_;
//QHash<TextThreadDelegate *, TextThreadDelegate *> Ihf::linkedDelegates_;
QHash<QString, ulong> Ihf::hookAddresses_;

char Ihf::keptThreadName_[ITH_THREAD_NAME_CAPACITY];

bool Ihf::whitelistEnabled_;
qint32 Ihf::whitelist_[Ihf::WhitelistSize];

// Debugging output
//void Ihf::consoleOutput(const char *text)
//{ if (debug_) qDebug() << "texthook:console:" << text; }

//void Ihf::consoleOutputW(const wchar_t *text)
//{ if (debug_) qDebug() << "texthook:console:" << QString::fromWCharArray(text); }

void Ihf::init()
{
  IthInitSystemService();
  Host_Init();
}
void Ihf::destroy()
{
  Host_Destroy();
  IthCloseSystemService();
}

// See also: HelloITH/main.cpp
bool Ihf::load()
{
  // 12/20/2013: This would crash the error of failure to create QTimer
  //if (!parentWindow_)

    //::wm_register_hidden_class("vnrtexthook.class");
    //parentWindow_ = (WId)::wm_create_hidden_window("vnrtexthook.class", "vnrtexthook");

  DOUT("enter");
  if (hookManager_) {
    DOUT("leave: already loaded");
    return true;
  }

  // Single instance protection
  //HANDLE hMutex = ::OpenMutex(MUTEX_ALL_ACCESS, FALSE, ITH_MUTEX_NAME); // in kernel32.dll
  //if (hMutex != 0 || ::GetLastError() != ERROR_FILE_NOT_FOUND) {
  //  ::CloseHandle(hMutex);
  //  return false;
  //}

  // See: ITH/main.cpp
  //if (!IthInitSystemService()) {
  //  DOUT("leave: error: failed to init system service");
  //  return false;
  //}

  if (::Host_Open()) {
#ifdef WITH_LIB_WINMAKER
    if (!parentWindow_)
      parentWindow_ = (WId)::wm_create_hidden_window("vnrtexthook");
#endif // WITH_LIB_WINMAKER
    WinTimer::setGlobalWindow(parentWindow_);
    ::Host_GetHookManager(&hookManager_);
    if (hookManager_) {
      //::Host_GetSettings(&settings_);
      //settings_->debug = debug_;

      //hookManager_->RegisterConsoleCallback(consoleOutput);
      //hookManager_->RegisterConsoleWCallback(consoleOutputW);
      //hookManager_->RegisterProcessAttachCallback(processAttach);
      //hookManager_->RegisterProcessDetachCallback(processDetach);
      //hookManager_->RegisterProcessNewHookCallback(processNewHook);
      //hookManager_->RegisterThreadResetCallback(threadReset);
      hookManager_->RegisterThreadCreateCallback(threadCreate);
      hookManager_->RegisterThreadRemoveCallback(threadRemove);

      ::Host_Start();
    }
  } else
    ::Host_Close();
  DOUT("leave: hook manager =" << hookManager_);
  return hookManager_;
}

void Ihf::unload()
{
  DOUT("enter: hook manager =" << hookManager_);
  if (hookManager_) {
    //hookManager_->RegisterProcessAttachCallback(nullptr);
    //hookManager_->RegisterProcessDetachCallback(nullptr);
    //hookManager_->RegisterProcessNewHookCallback(nullptr);
    //hookManager_->RegisterThreadResetCallback(nullptr);
    hookManager_->RegisterThreadCreateCallback(nullptr);
    hookManager_->RegisterThreadRemoveCallback(nullptr);
    // Console output is not unregisterd to avoid segmentation fault
    //hookManager_->RegisterConsoleCallback(nullptr);

    ::Host_Close();
    hookManager_ = nullptr;
    //settings_ = nullptr;

#ifdef WITH_LIB_WINMAKER
    if (parentWindow_) {
      wm_destroy_window(parentWindow_);
      parentWindow_ = nullptr;
    }
#endif // WITH_LIB_WINMAKER
  }
  //if (parentWindow_) {
  //  wm_destroy_window(parentWindow_);
  //  parentWindow_ = nullptr;
  //}
  DOUT("leave");
}

// - Callbacks -

//DWORD Ihf::processAttach(DWORD pid)
//{
//  DOUT("enter");
//  Q_UNUSED(pid);
//  DOUT("leave");
//  return 0;
//}

//DWORD Ihf::processDetach(DWORD pid)
//{
//  DOUT("enter");
//  Q_UNUSED(pid);
//  DOUT("leave");
//  return 0;
//}

//DWORD Ihf::processNewHook(DWORD pid)
//{
//  DOUT("enter");
//  Q_UNUSED(pid);
//  DOUT("leave");
//  return 0;
//}

// See: HelloITH/main.cpp
// See: ThreadCreate in ITH/window.cpp
DWORD Ihf::threadCreate(TextThread *t)
{
  Q_ASSERT(t);
  DOUT("enter: pid =" << t->PID());
  Q_ASSERT(hookManager_);

  // Propagate UNICODE
  // See: ThreadCreate in ITH/window.cpp
  //if (ProcessRecord *pr = hookManager_->GetProcessRecord(t->PID())) {
  //  NtWaitForSingleObject(pr->hookman_mutex, 0, 0);
  //  Hook *hk = static_cast<Hook *>(pr->hookman_map);
  //  Q_ASSERT(!hk&&!MAX_HOOK || hk&&MAX_HOOK);
  //  for (int i = 0; i < MAX_HOOK; i++) {
  //    if (hk[i].Address() == t->Addr()) {
  //      if (hk[i].Type() & USING_UNICODE)
  //        t->Status() |= USING_UNICODE;
  //      break;
  //    }
  //  }
  //  NtReleaseMutant(pr->hookman_mutex, 0);
  //}
  auto d = new TextThreadDelegate(t);
  bool init = true;
  foreach (TextThreadDelegate *it, threadDelegates_)
    if (d->signature() == it->signature()) {
      TextThreadDelegate::release(d);
      d = it;
      d->retain();
      init = false;
      break;
    }
  if (init) {
    d->setInterval(messageInterval_);
    d->setParentWindow(parentWindow_);
    updateLinkedDelegate(d);
  }
  threadDelegates_[t] = d;
  t->RegisterOutputCallBack(threadOutput, d);
  //t->RegisterFilterCallBack(threadFilter, d);
  DOUT("leave");
  return 0;
}

// See also: HelloITH/main.cpp
DWORD Ihf::threadRemove(TextThread *t)
{
  DOUT("enter");
  Q_ASSERT(t);

  auto p = threadDelegates_.find(t);
  if (p != threadDelegates_.end()) {
    auto d = p.value();
    //if (!linkedDelegates_.isEmpty()) {
    //  linkedDelegates_.remove(d);
    //  while (auto k = linkedDelegates_.key(d))
    //    linkedDelegates_.remove(k);
    //}
    threadDelegates_.erase(p);
    TextThreadDelegate::release(d);
  }

#ifdef ITH_WITH_LINK
  ::Host_UnLinkAll(t->Number());
#endif // ITH_WITH_LINK

  DOUT("leave");
  return 0;
}

// See: HelloITH/main.cpp
DWORD Ihf::threadOutput(TextThread *t, BYTE *data, DWORD dataLength, DWORD newLine, PVOID pUserData, bool space)
{
  DOUT("newLine =" << newLine << ", dataLength =" << dataLength << ", space =" << space);
  Q_UNUSED(t)
  Q_ASSERT(data);
  Q_ASSERT(pUserData);

  auto d = static_cast<TextThreadDelegate *>(pUserData);
  //if (TextThreadDelegate *link = findLinkedDelegate(d))
  //  d = link;
  Q_ASSERT(d);
  if (!enabled_ ||
      whitelistEnabled_ &&
      !whitelistContains(d->signature()) &&
      !(keptThreadName_[0] && d->nameEquals(keptThreadName_))) {
    DOUT("leave: ignored");
    return dataLength;
  }
  if (newLine)
    d->touch();
    //d->flush(); // new line data are ignored
  else if (dataLength || space)
    d->append(reinterpret_cast<char *>(data), dataLength, space);
  //QString text = QString::fromLocal8Bit(reinterpret_cast<LPCSTR>(data), len);
  DOUT("leave");
  return dataLength;
}

//TextThreadDelegate *Ihf::findLinkedDelegate(TextThreadDelegate *d)
//{
//  Q_ASSERT(d);
//  if (!linkedDelegates_.isEmpty()) {
//    auto p = linkedDelegates_.find(d);
//    if (p != linkedDelegates_.end())
//      return p.value();
//  }
//  return nullptr;
//}

void Ihf::updateLinkedDelegate(TextThreadDelegate *d)
{
#ifdef ITH_WITH_LINK
  Q_ASSERT(t);
  foreach (TextThreadDelegate *it, threadDelegates_)
    if (it->delegateOf(d))
      ::Host_AddLink(d->threadNumber(), it->threadNumber());
    else if (d->delegateOf(it))
      ::Host_AddLink(it->threadNumber(), d->threadNumber());
#else
  Q_UNUSED(d);
#endif // ITH_WITH_LINK
}

// - Injection -

// See: Host_InjectByPID in IHF/main.cpp
// See: InjectThread in ITH/profile.cpp
bool Ihf::attachProcess(DWORD pid)
{
  DOUT("enter: pid =" << pid);
  bool ok = ::Host_InjectByPID(pid);

  //enum { AttachDelay = 500 }; // in msec
  //::Sleep(AttachDelay);

  DOUT("leave: ret =" << ok);
  return ok;
}

// See: Host_ActiveDetachProcess in IHF/main.cpp
bool Ihf::detachProcess(DWORD pid) { return ::Host_ActiveDetachProcess(pid); }
bool Ihf::hijackProcess(DWORD pid) { return ::Host_HijackProcess(pid); }

// - Hook -

// See: Host_ModifyHook in IHF/main.cpp
bool Ihf::updateHook(ulong pid, const QString &code)
{
  DOUT("enter: pid =" << pid << ", code =" << code);
  Q_ASSERT(pid);
  HookParam hp = {};
  if (!Ith::parseHookCode(code, &hp)) {
    DOUT("leave: failed to parse hook code");
    return false;
  }

  DWORD hh = ::Host_ModifyHook(pid, &hp);
  bool ok = ~hh;
  DOUT("leave: ret =" << ok);
  return ok;
}

// See: Host_InsertHook in IHF/main.cpp
bool Ihf::addHook(ulong pid, const QString &code, const QString &name, bool verbose)
{
  DOUT("enter: pid =" << pid << ", name =" << name << ", code =" << code);
  Q_ASSERT(pid);
  if (hookAddresses_.contains(code)) {
    DOUT("leave: already added");
    return false;
  }

  HookParam hp = {};
  if (!Ith::parseHookCode(code, &hp, verbose)) {
    DOUT("leave: failed to parse hook code");
    return false;
  }

  DWORD hh = ::Host_InsertHook(pid, &hp, name.toAscii());
  //DWORD hh = ::NewHook(hp, nameBuf);
  bool ok = ~hh;
  if (ok && hp.address) {
    DOUT("hook address =" << hp.address);
    hookAddresses_[code] = hp.address;
  }
  DOUT("leave: ok =" << ok);
  return ok;
}

// See: Host_RemoveHook in IHF/main.cpp
bool Ihf::removeHook(ulong pid, const QString &code)
{
  DOUT("enter: pid =" << pid << ", code =" << code);
  Q_ASSERT(pid);
  auto p = hookAddresses_.find(code);
  if (p == hookAddresses_.end()) {
    DOUT("leave: hook not added");
    return false;
  }
  DWORD addr = p.value();
  Q_ASSERT(addr);
  hookAddresses_.erase(p);

  DWORD hh = ::Host_RemoveHook(pid, addr);
  bool ok = ~hh;
  DOUT("leave: ret =" << ok);
  return ok;
}

bool Ihf::verifyHookCode(const QString &code)
{ return Ith::verifyHookCode(code); }

// - Whitelist -

QList<qint32> Ihf::whitelist()
{
  QList<qint32> ret;
  const qint32 *p = whitelist_;
  while (*p)
    ret.append(*p++);
  return ret;
}

void Ihf::clearWhitelist() { *whitelist_= 0; }

void Ihf::setWhitelist(const QList<qint32> &l)
{
  qint32 *p = whitelist_;
  if (!l.isEmpty())
    foreach (qint32 it, l) {
      *p++ = it;
      if (p >= whitelist_ + WhitelistSize)
        break;
    }
  whitelist_[qMin(l.size(), WhitelistSize -1)] = 0;
}

bool Ihf::whitelistContains(qint32 signature)
{
  const qint32 *p = whitelist_;
  while (*p)
    if (signature == *p++)
      return true;
  return false;
}

// EOF

/*
BYTE LeadByteTable[0x100] = {
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1
};

DWORD Ihf::threadFilter(TextThread *thread, BYTE *out, DWORD len, DWORD new_line, PVOID data)
{
    DWORD status = thread->Status();

    if (!new_line && thread->Number() != 0)
    {
        if (status & USING_UNICODE)
        {
            DWORD i, j;
            len >>= 1;
            WCHAR c, *str = (LPWSTR)out;
            for (i = 0, j = 0; i < len; i++)
            {
                c = str[i];
                //if (!uni_filter->Check(c))
                  str[j++] = c;

            }
            memset(str + j, 0, (len - j) << 1);
            len = j << 1;
        }
        else
        {
            WORD c;
            DWORD i, j;
            for (i = 0, j = 0; i < len; i++)
            {
                c = out[i];
                if (LeadByteTable[c] == 1)
                {
                    //if (!mb_filter->Check(c))
                      out[j++] = c & 0xFF;
                }
                else if (i + 1 < len)
                {

                    c = out[i + 1];
                    c <<= 8;
                    c |= out[i];
                    //if (!mb_filter->Check(c))
                    {
                        out[j++] = c & 0xFF;
                        out[j++] = c >> 8;
                    }
                    i++;
                }
            }
            memset(out + j, 0, len - j);
            len = j;
        }
    }
    return len;
}
*/


/*
// jichi: 10/15/2011: FIXME: This overload will infect the entire program,
// even source files that exclude this header, which is unexpected.
// No idea what is the trade off of this behavior on performance and liability.
// Lots of Qt stuff doesn't work such as QString::toStdString.
// I have to use dynamic linkage to avoid being polluted by this module.
//
// original author: HEAP_ZERO_MEMORY flag is critical. All new object are assumed with zero initialized.
// jichi: 10/20/2011: I think the only reason to use Rtl heap here is to ensure HEAP_ZERO_MEMORY,
// which is really a bad programming style and incur unstability on heap memory allocation.
// ::RtlFreeHeap crash on DLL debug mode. Replace it with standard malloc/free.
// ::hHeap handle is also removed from ith/sys.c.cc

inline void * __cdecl operator new(size_t lSize)
{ return ::RtlAllocateHeap(::hHeap, HEAP_ZERO_MEMORY, lSize); }

inline void * __cdecl operator new[](size_t lSize)
{ return ::RtlAllocateHeap(::hHeap, HEAP_ZERO_MEMORY, lSize); }

inline void __cdecl operator delete(void *pBlock)
{ ::RtlFreeHeap(::hHeap, 0, pBlock); }

inline void __cdecl operator delete[](void* pBlock)
{ ::RtlFreeHeap(::hHeap, 0, pBlock); }


#include <cstdlib>
#include <cstring>
inline void * __cdecl operator new(size_t size) throw()
{
  if (!size)    // When the value of the expression in a direct-new-declarator is zero,
    size = 4;   // the allocation function is called to allocatean array with no elements.(ISO)

  void *p = malloc(size);
  if (p)
    memset(p, 0, size);
  return p;
}

inline void * __cdecl operator new[](size_t size) throw()
{
  if (!size)    // When the value of the expression in a direct-new-declarator is zero,
    size = 4;   // the allocation function is called to allocatean array with no elements.(ISO)

  void *p = malloc(size);
  if (p)
    memset(p, 0, size);
  return p;
}

inline void __cdecl operator delete(void *p) throw() { free(p); }
inline void __cdecl operator delete[](void *p) throw() { free(p); }
*/


//QString
//Ihf::getHookNameById(ulong hookId)
//{
//  QString ret;
//  if (hookId) {
//    auto p = reinterpret_cast<TextThread *>(hookId);
//    if (p->good())
//      ret = p->name();
//  }
//  return ret;
//}

//DWORD ProcessAttach(DWORD pid)
//{
//  DOUT("process attached, pid =" << pid);
//  return 0;
//}
//DWORD ProcessDetach(DWORD pid)
//{
//  DOUT("process detached, pid =" << pid);
//  return 0;
//}
//DWORD ProcessNewHook(DWORD pid)
//{
//  DOUT("process has new hook inserted, pid =" << pid);
//  return 0;
//}

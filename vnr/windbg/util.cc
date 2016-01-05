// windbg/util.cc
// 1/27/2013 jichi
#include "windbg/util.h"
#include <tlhelp32.h>
#include <boost/foreach.hpp>
#include <list>

WINDBG_BEGIN_NAMESPACE

class ThreadsSuspenderPrivate
{
public:
  std::list<HANDLE> threads;
};

ThreadsSuspender::ThreadsSuspender(bool autoSuspend)
  : d_(new D)
{ if (autoSuspend) suspend(); }

ThreadsSuspender::~ThreadsSuspender()
{
  resume();
  delete d_;
}

void ThreadsSuspender::suspend()
{
  HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (hSnap == INVALID_HANDLE_VALUE)
    return;
  THREADENTRY32 entry;
  entry.dwSize = sizeof(entry);
  DWORD pid = ::GetCurrentProcessId();
  DWORD tid = ::GetCurrentThreadId();
  if (::Thread32First(hSnap, &entry))
    do if (entry.dwSize >= 4 * sizeof(DWORD) && entry.th32OwnerProcessID == pid && entry.th32ThreadID != tid) {
      if (HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID)) {
        if (::SuspendThread(hThread) != DWORD(-1))
          d_->threads.push_back(hThread);
        else
          ::CloseHandle(hThread);
      }
      entry.dwSize = sizeof(entry);
    } while (::Thread32Next(hSnap, &entry));
  ::CloseHandle(hSnap);
}

void ThreadsSuspender::resume()
{
  if (!d_->threads.empty()) {
    BOOST_FOREACH (HANDLE hThread, d_->threads) {
      ::ResumeThread(hThread);
      ::CloseHandle(hThread);
    }
    d_->threads.clear();
  }
}

WINDBG_END_NAMESPACE

// EOF

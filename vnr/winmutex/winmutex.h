#pragma once
// winmutex.h
// 12/11/2011 jichi

#include <windows.h>

#ifdef _MSC_VER
# pragma warning(disable:4800) // C4800: forcing value to bool
#endif // _MSC_VER

// Mutex lock
// The interface of this class is consistent with the mutex class

template <typename _Mutex>
  class win_mutex_lock
  {
    typedef win_mutex_lock<_Mutex> _Self;
    win_mutex_lock(const _Self&);
    _Self &operator=(const _Self&);

    _Mutex &_M_mutex;
    bool _M_locked;
  public:
    typedef _Mutex mutex_type;
    typedef typename _Mutex::native_handle_type native_handle_type;
    explicit win_mutex_lock(mutex_type &mutex)
      : _M_mutex(mutex), _M_locked(false) { lock(); }
    ~win_mutex_lock() { if (_M_locked) _M_mutex.unlock(); }
    mutex_type &mutex() { return _M_mutex; }
    //bool isLock() const { return _M_locked; }
    native_handle_type native_handle() { return _M_mutex.native_handle(); }
    void unlock() { _M_mutex.unlock(); _M_locked = false; }
    void lock() { _M_mutex.lock(); _M_locked = true; }
    bool try_lock() { return _M_locked = _M_mutex.try_lock(); }
  };

// Mutex

template <typename _Mutex, size_t _Irql = 0>
  class win_mutex
  {
    typedef win_mutex<_Mutex> _Self;
    typedef _Mutex __native_type;
    enum { __minimal_irql = _Irql };
    __native_type _M_mutex;

    win_mutex(const _Self&);
    _Self &operator=(const _Self&);
  private:
    win_mutex() {}
    typedef __native_type *native_handle_type;
    native_handle_type native_handle() { return &_M_mutex; }
    static size_t minimal_irql() { return __minimal_irql; }

    void unlock() {}
    void lock() {}
    bool try_lock() {}
  };

template <>
  class IHFSERVICE win_mutex<CRITICAL_SECTION>
  {
    typedef win_mutex<CRITICAL_SECTION> _Self;
    typedef CRITICAL_SECTION __native_type;
    enum { __minimal_irql = 0 };
    win_mutex(const _Self&);
    _Self &operator=(const _Self&);

    __native_type _M_mutex;
  public:
    typedef __native_type *native_handle_type;
    native_handle_type native_handle() { return &_M_mutex; }
    static size_t minimal_irql() { return __minimal_irql; }

    win_mutex() { ::InitializeCriticalSection(&_M_mutex); }
    ~win_mutex() { ::DeleteCriticalSection(&_M_mutex); }
    void lock() { ::EnterCriticalSection(&_M_mutex); }
    void unlock() { ::LeaveCriticalSection(&_M_mutex); }
    bool try_lock() { return ::TryEnterCriticalSection(&_M_mutex); }
  };

// Conditional variable

template <typename _Cond>
  class win_mutex_cond
  {
    typedef win_mutex_cond<_Cond> _Self;
    typedef _Cond __native_type;
    win_mutex_cond(const _Self&);
    _Self &operator=(const _Self&);

    __native_type _M_cond;
  public:
    enum wait_status { no_timeout = 0, timeout };
    typedef __native_type *native_handle_type;

    win_mutex_cond() {}
    native_handle_type native_handle() { return &_M_cond; }

    void notify_one() {}
    void notify_all() {}

    template <typename _Mutex>
    void wait(_Mutex &mutex) {}

    template <typename _Mutex, typename _Pred>
    void wait(_Mutex &mutex, _Pred pred) {}

    template <typename _Mutex>
    wait_status wait_for(_Mutex &mutex, int msecs) {}

    template <typename _Mutex, typename _Pred>
    wait_status wait_for(_Mutex &mutex, int msecs, _Pred pred) {}
  };

// Note: Conditional variables are NOT availabe on Windows XP/2003
// See: http://en.cppreference.com/w/cpp/thread/condition_variable
// See: http://msdn.microsoft.com/en-us/library/windows/desktop/ms686903%28v=vs.85%29.aspx
template <>
  class win_mutex_cond<CONDITION_VARIABLE>
  {
    typedef win_mutex_cond<CONDITION_VARIABLE> _Self;
    typedef CONDITION_VARIABLE __native_type;
    win_mutex_cond(const _Self&);
    _Self &operator=(const _Self&);

    __native_type _M_cond;
  public:
    enum wait_status { no_timeout = 0, timeout };
    typedef __native_type *native_handle_type;
    native_handle_type native_handle() { return &_M_cond; }

    win_mutex_cond() { ::InitializeConditionVariable(&_M_cond); }

    void notify_one() { ::WakeConditionVariable(&_M_cond); }
    void notify_all() { ::WakeAllConditionVariable(&_M_cond); }

    template <typename _Mutex>
    void wait(_Mutex &mutex)
    { ::SleepConditionVariableCS(&_M_cond, mutex.native_handle(), INFINITE); }

    template <typename _Mutex, typename _Pred>
    void wait(_Mutex &mutex, _Pred pred)
    { while (!pred()) wait(mutex); }

    template <typename _Mutex>
    wait_status wait_for(_Mutex &mutex, int msecs)
    { return ::SleepConditionVariableCS(&_M_cond, mutex.native_handle(), msecs) ? no_timeout : timeout; }

    template <typename _Mutex, typename _Pred>
    wait_status wait_for(_Mutex &mutex, int msecs, _Pred pred)
    {
      auto start = ::GetTickCount();
      while (!pred()) {
        auto now = ::GetTickCount();
        msecs -= now - start;
        if (msecs <= 0)
          return timeout;
        start = now;
        wait_for(mutex, msecs);
      }
      return no_timeout;
    }
  };

// EOF

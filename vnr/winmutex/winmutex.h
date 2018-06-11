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

  class MutexLocker
  {
	  HANDLE m;
  public:
	  explicit MutexLocker(HANDLE mutex) : m(mutex)
	  {
		  WaitForSingleObject(m, 0);
	  }
	  ~MutexLocker() { if (m != INVALID_HANDLE_VALUE && m != nullptr) ReleaseMutex(m); }
  };

// EOF

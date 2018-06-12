#pragma once
// textthread_p.h
// 8/14/2013 jichi
// Branch: ITH/main_template.h, rev 66

#include <windows.h>

template <typename T>
void Release(const T &p) { delete p; }

// Prevent memory release.
// Used when T is basic types and will be automatically released (on stack).
#define MK_BASIC_TYPE(T) \
  template<> \
  void Release<T>(const T &p) {}

template<class T, int default_size>
class MyVector
{
public:
	int Used() const { return used; }
	T *Storage() const { return storage; }
	void LockVector() { EnterCriticalSection(&cs_store); }
	void UnlockVector() { LeaveCriticalSection(&cs_store); }
  MyVector() : size(default_size), used(0)
  {
    InitializeCriticalSection(&cs_store);
    storage = new T[size];
    // jichi 9/21/2013: zero memory
    // This would cause trouble if T is not an atomic type
    ::memset(storage, 0, sizeof(T) * size);
  }

  virtual ~MyVector()
  {
    if (storage)
      delete[] storage;
    DeleteCriticalSection(&cs_store);
    storage = 0;
  }
protected:

  void Reset()
  {
    EnterCriticalSection(&cs_store);
    for (int i = 0; i < used; i++) {
      Release<T>(storage[i]);
      storage[i] = T();
    }
    used = 0;
    LeaveCriticalSection(&cs_store);
  }
  void Remove(int index)
  {
    if (index>=used)
      return;
    Release<T>(storage[index]);
    for (int i = index; i < used; i++)
      storage[i] = storage[i+1];
    used--;
  }
  void ClearMemory(int offset, int clear_size)
  {
    if (clear_size < 0)
      return;
    EnterCriticalSection(&cs_store);
    if (offset+clear_size <= size)
      ::memset(storage+offset, 0, clear_size * sizeof(T)); // jichi 11/30/2013: This is the original code of ITH
    LeaveCriticalSection(&cs_store);
    //else __asm int 3
  }
  int AddToStore(T *con,int amount)
  {
    if (amount <= 0 || con == 0)
      return 0;
    int status = 0;
    EnterCriticalSection(&cs_store);
    if (amount + used + 2 >= size) {
      while (amount + used + 2 >= size)
        size<<=1;
      T *temp;
      if (size * sizeof(T) < 0x1000000) {
        temp = new T[size];
        if (size > used)
          ::memset(temp, 0, (size - used) * sizeof(T)); // jichi 9/25/2013: zero memory
        memcpy(temp, storage, used * sizeof(T));
      } else {
        size = default_size;
        temp = new T[size];
        ::memset(temp, 0, sizeof(T) * size); // jichi 9/25/2013: zero memory
        used = 0;
        status = 1;
      }
      delete[] storage;
      storage = temp;
    }
    memcpy(storage+used, con, amount * sizeof(T));
    used += amount;
    LeaveCriticalSection(&cs_store);
    return status;
  }

  CRITICAL_SECTION cs_store;
  int size,
      used;
  T *storage;
};

// EOF

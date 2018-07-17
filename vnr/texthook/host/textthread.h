#pragma once

// textthread.h
// 8/23/2013 jichi
// Branch: ITH/TextThread.h, rev 120

#include "host/textthread_p.h"
#include <intrin.h> // require _InterlockedExchange
#include <string>
#include <vector>

struct ThreadParameter {
  DWORD pid; // jichi: 5/11/2014: The process ID
  DWORD hook; // Artikash 6/6/2018: The start address of the hook
  DWORD retn; // jichi 5/11/2014: The return address of the hook
  DWORD spl;  // jichi 5/11/2014: the processed split value of the hook paramete
			  
  // Artikash 5/31/2018: required for unordered_map to work with struct key
  friend bool operator==(const ThreadParameter& one, const ThreadParameter& two)
  {
	  return one.pid == two.pid && one.hook == two.hook && one.retn == two.retn && one.spl == two.spl;
  }
};

#define CURRENT_SELECT 0x1000

class TextThread;
typedef DWORD (* ThreadOutputFilterCallback)(TextThread *,const BYTE *, DWORD, DWORD);
typedef DWORD (* ThreadEventCallback)(TextThread *);

//extern DWORD split_time,repeat_count,global_filter,cyclic_remove;

class TextThread : public MyVector<BYTE, 0x200>
{
public:
  TextThread(ThreadParameter tp, unsigned int threadNumber, unsigned int splitDelay);

  virtual void GetEntryString(LPSTR buffer, DWORD max);

  void Reset();
  void AddText(const BYTE *con,int len);
  void AddSentence();
  void AddSentence(std::wstring sentence);

  BYTE *GetStore(DWORD *len) { if (len) *len = used; return storage; }
  DWORD PID() const { return tp.pid; }
  DWORD Addr() const {return tp.hook; }
  DWORD &Status() { return status; }
  WORD Number() const { return thread_number; }
  ThreadParameter *GetThreadParameter() { return &tp; }
  //LPCWSTR GetComment() { return comment; }

  ThreadOutputFilterCallback RegisterOutputCallBack(ThreadOutputFilterCallback cb, PVOID data)
  {
    return (ThreadOutputFilterCallback)_InterlockedExchange((long*)&output,(long)cb);
  }

private:
  ThreadParameter tp;
  ThreadOutputFilterCallback output;
  std::vector<char> sentenceBuffer;
  unsigned int thread_number;
  unsigned int splitDelay;
  DWORD status;
};

// EOF

#pragma once

// textthread.h
// 8/23/2013 jichi
// Branch: ITH/TextThread.h, rev 120

#include "host/textthread_p.h"
#include <intrin.h> // require _InterlockedExchange
#include <string>
#include <vector>

struct RepeatCountNode {
  short repeat;
  short count;
  RepeatCountNode *next;

  //RepeatCountNode() : repeat(0), count(0), next(nullptr) {}
};

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
#define REPEAT_NUMBER_DECIDED  0x2000
#define BUFF_NEWLINE 0x4000
#define CYCLIC_REPEAT 0x8000
#define COUNT_PER_FOWARD 0x200
#define REPEAT_DETECT 0x10000
#define REPEAT_SUPPRESS 0x20000
#define REPEAT_NEWLINE 0x40000

class TextThread;
typedef void (* ConsoleCallback)(LPCSTR text);
typedef void (* ConsoleWCallback)(LPCWSTR text);
typedef DWORD (* ThreadOutputFilterCallback)(TextThread *,const BYTE *, DWORD, DWORD);
typedef DWORD (* ThreadEventCallback)(TextThread *);

//extern DWORD split_time,repeat_count,global_filter,cyclic_remove;

class TextThread : public MyVector<BYTE, 0x200>
{
public:
  TextThread(ThreadParameter tp, WORD num);

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

  std::vector<char> sentenceBuffer;
  WORD thread_number;
  ThreadOutputFilterCallback output;
  DWORD status;
};

// EOF

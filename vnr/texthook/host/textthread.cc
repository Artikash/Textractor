// textthread.cc
// 8/24/2013 jichi
// Branch IHF/TextThread.cpp, rev 133
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "settings.h"
#include "textthread.h"
//#include "wintimer/wintimer.h"
#include "vnrhook/include/const.h"
#include "ithsys/ithsys.h"
#include <stdio.h>
#include "extensions/Extensions.h"

MK_BASIC_TYPE(BYTE)
MK_BASIC_TYPE(ThreadParameter)

static DWORD MIN_DETECT = 0x20;
static DWORD MIN_REDETECT = 0x80;
//#define MIN_DETECT    0x20
//#define MIN_REDETECT  0x80
#ifndef CURRENT_SELECT
# define CURRENT_SELECT        0x1000
#endif
#ifndef REPEAT_NUMBER_DECIDED
# define REPEAT_NUMBER_DECIDED  0x2000
#endif

DWORD GetHookName(LPSTR str, DWORD pid, DWORD hook_addr,DWORD max);

extern Settings *settings;
extern HWND dummyWindow;
void CALLBACK NewLineBuff(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
  KillTimer(hwnd,idEvent);
  TextThread *id=(TextThread*)idEvent;
    id->DispatchLastSentence();
  
  //id->SendLastToExtension();
  id->SetNewLineFlag();
}

// jichi 10/27/2013: removed
//void CALLBACK NewLineConsole(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
//{
//  KillTimer(hwnd,idEvent);
//  TextThread *id=(TextThread*)idEvent;
//  if (id->Status()&USING_UNICODE)
//    id->AddText((BYTE*)L"\r\n",4,true,true);
//  if (id->Status()&CURRENT_SELECT)
//  {
//    //texts->SetLine();
//  }
//}

// jichi 10/27/2013: removed
//void ReplaceSentence(BYTE* text, int len)
//{
//  __asm int 3
//}

TextThread::TextThread(DWORD id, DWORD hook, DWORD retn, DWORD spl, WORD num) :
  //,tp
  thread_number(num)
  // jichi 9/21/2013: zero all fields
  , link_number(-1)
  , last (0)
  , align_space(0)
  , repeat_single(0)
  , repeat_single_current(0)
  , repeat_single_count(0)
  , repeat_detect_count(0)
  , head(new RepeatCountNode())
  , link(nullptr)
  //, filter(nullptr)
  , output(nullptr)
  , app_data(nullptr)
  //, comment(nullptr)
  , thread_string(nullptr)
  , timer(0)
  , status (0)
  , repeat_detect_limit(0x80)
  , last_sentence(0)
  , prev_sentence(0)
  , sentence_length(0)
  , repeat_index(0)
  , last_time(0)
//  , tp({id, hook, retn, spl})
{
  tp.pid = id;
  tp.hook = hook;
  tp.retn = retn;
  tp.spl = spl;
  //head = new RepeatCountNode;
  //::memset(head, 0, sizeof(RepeatCountNode)); // jichi 9/21/2013: zero memory
  //link_number = -1;
  //repeat_detect_limit = 0x80;
  //filter = nullptr;
  //output = nullptr;
}
TextThread::~TextThread()
{
  //KillTimer(dummyWindow,timer);
  RepeatCountNode *t = head,
                  *tt;
  while (t) {
    tt = t;
    t = tt->next;
    delete tt;
  }
  head = nullptr;
  //if (comment) {
  //  delete[] comment;
  //  comment = nullptr;
  //}
  if (thread_string)
    delete[] thread_string;
}
void TextThread::Reset()
{
  //timer=0;
  last_sentence = 0;
  //if (comment) {
  //  delete[] comment;
  //  comment = nullptr;
  //}
  MyVector::Reset();
}
void TextThread::RemoveSingleRepeatAuto(const BYTE *con, int &len)
{
#ifdef ITH_DISABLE_REPEAT // jichi 9/28/2013: only for debugging purpose
  return;
#endif // ITH_DISABLE_REPEAT
  WORD *text = (WORD *)con;
  if (len <= 2) {
    if (repeat_single) {
      if (repeat_single_count<repeat_single&&
          last == *text) {
        len = 0;
        repeat_single_count++;
      } else {
        last = *text;
        repeat_single_count=0;
      }
    }
    if (status & REPEAT_NUMBER_DECIDED) {
      if (++repeat_detect_count>MIN_REDETECT) {
        repeat_detect_count = 0;
        status ^= REPEAT_NUMBER_DECIDED;
        last = 0;
        RepeatCountNode *t = head,
                        *tt;
        while (t) {
          tt = t;
          t = tt->next;
          delete tt;
        }
        head = new RepeatCountNode;
        ::memset(head, 0, sizeof(RepeatCountNode)); // jichi 9/21/2013: zero memory
      }
    } else {
      repeat_detect_count++;
      if (last == *text)
        repeat_single_current++;
      else {
        if (last == 0) {
          last = *text;
          return;
        }
        if (repeat_single_current == 0) {
          status |= REPEAT_NUMBER_DECIDED;
          repeat_single = 0;
          return;
        }
        last = *text;
        RepeatCountNode *it = head;
        if (repeat_detect_count > MIN_DETECT) {
          while (it = it->next)
            if (it->count>head->count) {
              head->count=it->count;
              head->repeat=it->repeat;
            }
          repeat_single = head->repeat;
          repeat_single_current = 0;
          repeat_detect_count = 0;
          status |= REPEAT_NUMBER_DECIDED;
          DWORD repeat_sc = repeat_single*4;
          if (repeat_sc > MIN_DETECT) {
            MIN_DETECT <<= 1;
            MIN_REDETECT <<= 1;
          }
        } else {
          bool flag=true;
          while (it) {
            if (it->repeat == repeat_single_current) {
              it->count++;
              flag = false;
              break;
            }
            it=it->next;
          }
          if (flag) {
            RepeatCountNode *n = new RepeatCountNode;
            n->count = 1;
            n->repeat = repeat_single_current;
            n->next = head->next;
            head->next = n;
          }
          repeat_single_current = 0;
        } //Decide repeat_single
      } //Check Repeat
    } //repeat_single decided?
  } //len
  else {
    status |= REPEAT_NUMBER_DECIDED;
    repeat_single = 0;
  }
}

void TextThread::ResetRepeatStatus()
{
  last=0;
  repeat_single=0;
  repeat_single_current=0;
  repeat_single_count=0;
  repeat_detect_count=0;
  RepeatCountNode *t = head->next,
                  *tt;
  while (t) {
    tt = t;
    t = tt->next;
    delete tt;
  }
  //head=new RepeatCountNode;
  head->count = head->repeat = 0;
  status &= ~REPEAT_NUMBER_DECIDED;
}
void TextThread::AddLineBreak()
{
  if (sentence_length == 0) return;
  if (status&BUFF_NEWLINE)
  {
    prev_sentence=last_sentence;
    sentence_length=0;
    if (status & USING_UNICODE)
      AddToStore((BYTE *)L"\r\n\r\n", 8);
    else
      AddToStore((BYTE *)"\r\n\r\n", 4);
    if (output)
      output(this, 0, 8, TRUE, app_data, false); // jichi 10/27/2013: space is false
    last_sentence = used;
    status &= ~BUFF_NEWLINE;
  }
}
void TextThread::AddText(const BYTE *con, int len, bool new_line, bool space)
{
  if (!con || (len <= 0 && !space))
    return;
  if (len && !new_line) {
    // jichi 9/1/2013: manual repetition count removed
    //if (setman->GetValue(SETTING_REPEAT_COUNT)) {
    //  status|=REPEAT_NUMBER_DECIDED;
    //  RemoveSingleRepeatForce(con,len);
    //}
    //else
    RemoveSingleRepeatAuto(con, len);
    if (len <= 0 && !space)
      return;
  }

  // jichi 9/1/2013: manual repetition count removed
  //if(setman->GetValue(SETTING_CYCLIC_REMOVE)) {
  //  //if (status & REPEAT_NUMBER_DECIDED)
  //    RemoveCyclicRepeat(con,len);
  //}
  //if (len <= 0)
  //  return;

  // jichi 10/27/2013: User-defined filter callback is disabled
  //if (filter)
  //  len = filter(this, con,len, new_line, app_data);
  //if (len <= 0)
  //  return;

  if (len && sentence_length == 0) {
    if (status & USING_UNICODE) {
      if (*(WORD *)con == 0x3000) { // jichi 10/27/2013: why skip unicode space?!
        con += 2;
        len -= 2;
      }
    } else if (*(WORD *)con == 0x4081) {
      con += 2;
      len -= 2;
    }

    if (len <= 0 && !space)
      return;
  }

  if (status & BUFF_NEWLINE)
    AddLineBreak();

  if (len)
    if (new_line) {
      prev_sentence = last_sentence;
      last_sentence = used + 4;
      if (status & USING_UNICODE)
        last_sentence += 4;
      sentence_length = 0;
    } else {
      SetNewLineTimer();
      sentence_length += len;
    }

  BYTE *data = const_cast<BYTE *>(con); // jichi 10/27/2013: TODO: Figure out where con is modified
  if (output)
    len = output(this, data, len, new_line, app_data, space);
  if (AddToStore(data, len)) {
    //sentence_length += len;
    /*ResetRepeatStatus();
    last_sentence=0;
    prev_sentence=0;
    sentence_length=len;
    repeat_index=0;
    status&=~REPEAT_DETECT|REPEAT_SUPPRESS;    */
  }
}

DWORD TextThread::GetEntryString(LPSTR str, DWORD max)
{
  DWORD len = 0;
  if (str && max > 0x40) {
    max--;
    if (thread_string) {
      len = ::strlen(thread_string);
      len = len < max ? len : max;
      memcpy(str, thread_string, len);
      str[len] = 0;

    } else {
      len = ::sprintf(str, "%.4X:%.4d:0x%08X:0x%08X:0x%08X:",
          thread_number, tp. pid, tp.hook, tp.retn, tp.spl);

      len += GetHookName(str + len, tp.pid, tp.hook, max - len);
      thread_string = new char[len + 1];
      //::memset(thread_string, 0, (len+1) * sizeof(wchar_t)); // jichi 9/26/2013: zero memory
      thread_string[len] = 0;
      ::memcpy(thread_string, str, len);
    }
    //if (comment) {
    //  str += len;
    //  max--;
    //  DWORD cl = wcslen(comment);
    //  if (len + cl >= max)
    //    cl = max - len;
    //  *str++ = L'-';
    //  memcpy(str, comment, cl << 1);
    //  str[cl] = 0;
    //  len += cl;
    //}
  }
  return len;
}
// jichi 9/28/2013: removed
//void TextThread::CopyLastSentence(LPWSTR str)
//{
//  int i,j,l;
//  if (status&USING_UNICODE)
//  {
//    if (used>8)
//    {
//      j=used>0xF0?(used-0xF0):0;
//      for (i=used-0xA;i>=j;i-=2)
//      {
//        if (*(DWORD*)(storage+i)==0xA000D) break;
//      }
//      if (i>=j)
//      {
//        l=used-i;
//        if (i>j) l-=4;
//        j=4;
//      }
//      else
//      {
//        i+=2;
//        l=used-i;
//        j=0;
//      }
//      memcpy(str,storage+i+j,l);
//      str[l>>1]=0;
//    }
//    else
//    {
//      memcpy(str,storage,used);
//      str[used>>1]=0;
//    }
//  }
//  else
//  {
//    if (used>4)
//    {
//      j=used>0x80?(used-0x80):0;
//      for (i=used-5;i>=j;i--)
//      {
//        if (*(DWORD*)(storage+i)==0xA0D0A0D) break;
//      }
//      if (i>=j)
//      {
//        l=used-i;
//        if (i>j) l-=4;
//        j=4;
//      }
//      else
//      {
//        i++;
//        l=used-i;
//        j=0;
//      }
//      size_t sz = (l|0xF) + 1;
//      char *buff = new char[sz];
//      //memset(buff, 0, sz); // jichi 9/26/2013: zero memory
//      memcpy(buff, storage + i + j, l);
//      buff[l] = 0;
//      str[MB_WC(buff, str)] = 0;
//      delete[] buff;
//    } else {
//      storage[used] = 0;
//      str[MB_WC((char *)storage, str)] = 0;
//    }
//  }
//}

// jichi 8/25/2013: clipboard removed
void DispatchSentence(void* str,DWORD status, int len)
{
	char sentenceBuffer[0x400];
  if (str && len > 0)
  {
    int size=(len*2|0xF)+1;
    if (len>=1022) return;
    memcpy(sentenceBuffer,str,len);
    *(WORD*)(sentenceBuffer+len)=0;
    HGLOBAL hCopy;
    wchar_t copy[0x200];
	if (status&USING_UNICODE)
	{
		memcpy(copy, sentenceBuffer, len + 2);
	}
	else
		copy[MB_WC(sentenceBuffer, copy)] = 0;
	DispatchSentenceToExtensions(copy, status);
  }
}
void TextThread::DispatchLastSentence()
{
  // jichi 8/25/2013: clipboard removed
  DispatchSentence(storage+last_sentence,status,used-last_sentence);

}

//void TextThread::ResetEditText()
//{
//  //__asm int 3;
//  WCHAR str[0x20];
//  swprintf(str,L"%.8X",_ReturnAddress());
//}

// jichi 9/25/2013: Removed
//void TextThread::ExportTextToFile(LPWSTR) //filename)
//{
//  HANDLE hFile=IthCreateFile(filename,FILE_WRITE_DATA,0,FILE_OPEN_IF);
//  if (hFile==INVALID_HANDLE_VALUE) return;
//  EnterCriticalSection(&cs_store);
//  IO_STATUS_BLOCK ios;
//  LPVOID buffer=storage;
//  DWORD len=used;
//  BYTE bom[4]={0xFF,0xFE,0,0};
//  LARGE_INTEGER offset={2,0};
//  if ((status&USING_UNICODE)==0)
//  {
//    len=MB_WC_count((char*)storage,used);
//    buffer = new wchar_t[len+1];
//    MB_WC((char*)storage,(wchar_t*)buffer);
//    len<<=1;
//  }
//  NtWriteFile(hFile,0,0,0,&ios,bom,2,0,0);
//  NtWriteFile(hFile,0,0,0,&ios,buffer,len,&offset,0);
//  NtFlushBuffersFile(hFile,&ios);
//  if (buffer !=storage)
//    delete[] buffer;
//  NtClose(hFile);
//  LeaveCriticalSection(&cs_store);
//}

//void TextThread::SetComment(LPWSTR str)
//{
//  if (comment)
//    delete[] comment;
//  size_t sz = wcslen(str);
//  comment = new wchar_t[sz + 1];
//  comment[sz] = 0;
//  wcscpy(comment, str);
//}

void TextThread::SetNewLineFlag() { status |= BUFF_NEWLINE; }

void TextThread::SetNewLineTimer()
{
  if (thread_number == 0)
    // jichi 10/27/2013: Not used
    timer = 0; //SetTimer(dummyWindow,(UINT_PTR)this, settings->splittingInterval, NewLineConsole);
  else
	  timer = SetTimer(dummyWindow, (UINT_PTR)this, settings->splittingInterval, NewLineBuff);
}

// EOF

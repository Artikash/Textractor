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

TextThread::TextThread(ThreadParameter tp, WORD num) :
  //,tp
  thread_number(num)
  , output(nullptr)
  //, comment(nullptr)
  , timer(0)
  , status (0)
  , last_sentence(0)
  , sentence_length(0)
  , tp(tp)
{
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

void TextThread::AddLineBreak()
{
  if (sentence_length == 0) return;
  if (status&BUFF_NEWLINE)
  {
    sentence_length=0;
    if (status & USING_UNICODE)
      AddToStore((BYTE *)L"\r\n\r\n", 8);
    else
      AddToStore((BYTE *)"\r\n\r\n", 4);
    if (output)
      output(this, 0, 8, TRUE); // jichi 10/27/2013: space is false
    last_sentence = used;
    status &= ~BUFF_NEWLINE;
  }
}
void TextThread::AddText(const BYTE *con, int len, bool new_line)
{

  if (status & BUFF_NEWLINE)
    AddLineBreak();

  if (len)
    if (new_line) {
      last_sentence = used + 4;
      if (status & USING_UNICODE)
        last_sentence += 4;
      sentence_length = 0;
    } else {
      SetNewLineTimer();
      sentence_length += len;
    }

  if (len <= 0) return;
  BYTE *data = const_cast<BYTE *>(con); // jichi 10/27/2013: TODO: Figure out where con is modified
  if (output)
    len = output(this, data, len, new_line);
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

void TextThread::GetEntryString(LPSTR buffer, DWORD max)
{
    int len = sprintf(buffer, "%.4X:%.4d:0x%08X:0x%08X:0x%08X:",
          thread_number, tp. pid, tp.hook, tp.retn, tp.spl);
    GetHookName(buffer + len, tp.pid, tp.hook, max - len);
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
    wchar_t copy[0x400];
	if (status&USING_UNICODE)
	{
		memcpy(copy, sentenceBuffer, len + 2);
	}
	else
	{
		MultiByteToWideChar(932, 0, sentenceBuffer, -1, copy, 0x400);
	}
	DispatchSentenceToExtensions(copy, status);
  }
}
void TextThread::DispatchLastSentence()
{
  // jichi 8/25/2013: clipboard removed
  DispatchSentence(storage+last_sentence,status,used-last_sentence);

}

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

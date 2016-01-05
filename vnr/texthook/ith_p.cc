// ith_p.cc
// 10/15/2011 jichi

#include "texthook/ith_p.h"
#include "vnrhook/include/const.h"
#include "vnrhook/include/types.h"
#include <string>

#define DEBUG "ith_p.cc"
#include "sakurakit/skdebug.h"

// HookParam copied from ITH/common.h:
// struct HookParam // size = 40 (0x24)
// {
//   typedef void (*DataFun)(DWORD, HookParam*, DWORD*, DWORD*, DWORD*);
//
//   DWORD addr;         // 4
//   DWORD off,          // 8
//         ind,          // 12
//         split,        // 16
//         split_ind;    // 20
//   DWORD module,       // 24
//         function;     // 28
//   DataFun text_fun; // 32, jichi: is this the same in x86 and x86_64?
//   DWORD type;         // 36
//   WORD length_offset; // 38
//   BYTE hook_len,      // 39
//        recover_len;   // 40
// };


// - Implementation Details -

namespace { namespace detail { // unnamed

// ITH ORIGINAL CODE BEGIN

// See: ITH/ITH.h
// Revision: 133
inline DWORD Hash(_In_ LPWSTR module, int length = -1)
{
  bool flag = length == -1;
  DWORD hash = 0;
  for (; *module && (flag || length--); module++)
    hash = _rotr(hash,7) + *module; //hash=((hash>>7)|(hash<<25))+(*module);
  return hash;
}

// See: ITH/command.cpp
// Revision: 133
//
// jichi note: str[0xF] will be modified and restored.
// So, the buffer of str must be larger than 0xF.
int Convert(_In_ LPWSTR str, _Out_ DWORD *num, _In_ LPWSTR delim)
{
  if (!num)
    return -1;
  WCHAR t = *str,
        tc = *(str + 0xF);
  WCHAR temp[0x10] = {};
  LPWSTR it = temp,
         istr = str,
         id = temp;
  if (delim) {
    id = wcschr(delim, t);
    str[0xF] = delim[0];  // reset str[0xF] in case of out-of-bound iteration
  }
  else
    str[0xF] = 0;  // reset str[0xF] in case of out-of-bound iteration
  while (!id && t) {
    *it = t;
    it++; istr++;
    t = *istr;
    if (delim)
      id = wcschr(delim, t);
  }
  swscanf(temp, L"%x", num);
  str[0xF] = tc;  // restore the str[0xF]
  if (!id || istr - str == 0xF)
    return -1;

  if (!t)
    return istr - str; // >= 0
  else
    return id - delim; // >= 0
}

// See: ITH/command.cpp
// Revision: 133
//
// jichi note: str[0xF] will be modified and restored.
// So, the buffer of cmd must be larger than 0xF*2 = 0x1F.
bool Parse(_In_ LPWSTR cmd, _Out_ HookParam &hp)
{
  ::memset(&hp, 0, sizeof(hp));

  int t;
  bool accept = false;
  DWORD *data = &hp.offset;  //
  LPWSTR offset = cmd + 1;
  LPWSTR delim_str = L":*@!";
  LPWSTR delim = delim_str;
  if (*offset == L'n' || *offset == 'N') {
    offset++;
    hp.type |= NO_CONTEXT;
  }
  // jichi 4/25/2015: Add support for fixing hook
  if (*offset == L'f' || *offset == 'F') {
    offset++;
    hp.type |= FIXING_SPLIT;
  }
  if (*offset == L'j' || *offset == 'J') { // 11/22/2015: J stands for Japanese only
    offset++;
    hp.type |= NO_ASCII;
  }
  while (!accept) {
    t = Convert(offset, data, delim);
    if (t < 0)
      return false; //ConsoleOutput(L"Syntax error.");
    offset = ::wcschr(offset , delim[t]);
    if (offset)
      offset++;   // skip the current delim
    else //goto _error;
      return false; //ConsoleOutput(L"Syntax error.");
    switch (delim[t]) {
    case L':':
      data = &hp.split;
      delim = delim_str + 1;
      hp.type |= USING_SPLIT;
      break;
    case L'*':
      if (hp.split) {
        data = &hp.split_index;
        delim = delim_str + 2;
        hp.type |= SPLIT_INDIRECT;
      }
      else {
        hp.type |= DATA_INDIRECT;
        data = &hp.index;
      }
      break;
    case L'@':
      accept = true;
      break;
    }
  }
  t = Convert(offset, &hp.address, delim_str);
  if (t < 0)
    return false;
  if (hp.offset & 0x80000000)
    hp.offset -= 4;
  if (hp.split & 0x80000000)
    hp.split -= 4;
  LPWSTR temp = offset;
  offset = ::wcschr(offset, L':');
  if (offset) {
    hp.type |= MODULE_OFFSET;
    offset++;
    delim = ::wcschr(offset, L':');

    if (delim) {
      *delim = 0;
      delim++;
      _wcslwr(offset);
      hp.function = Hash(delim);
      hp.module = Hash(offset, delim - offset - 1);
      hp.type |= FUNCTION_OFFSET;
    }
    else
      hp.module = Hash(_wcslwr(offset));

  } else {
    offset = ::wcschr(temp, L'!');
    if (offset) {
      hp.type |= MODULE_OFFSET;
      swscanf(offset + 1, L"%x", &hp.module);
      offset = ::wcschr(offset + 1, L'!');
      if (offset) {
        hp.type |= FUNCTION_OFFSET;
        swscanf(offset + 1, L"%x", &hp.function);
      }
    }
  }
  switch (*cmd) {
  case L's':
  case L'S':
    hp.type |= USING_STRING;
    break;
  case L'e':
  case L'E':
    hp.type |= STRING_LAST_CHAR;
  case L'a':
  case L'A':
    hp.type |= BIG_ENDIAN;
    hp.length_offset = 1;
    break;
  case L'b':
  case L'B':
    hp.length_offset = 1;
    break;
  // jichi 12/7/2014: Disabled
  //case L'h':
  //case L'H':
  //  hp.type |= PRINT_DWORD;
  case L'q':
  case L'Q':
    hp.type |= USING_STRING | USING_UNICODE;
    break;
  case L'l':
  case L'L':
    hp.type |= STRING_LAST_CHAR;
  case L'w':
  case L'W':
    hp.type |= USING_UNICODE;
    hp.length_offset = 1;
    break;
  default: ;
  }
  //ConsoleOutput(L"Try to insert additional hook.");
  return true;
}

// ITH ORIGINAL CODE END

}} // unnamed detail

// - ITH API -

// Sample code: L"/HS-4:-14@4383C0" (WHITE ALBUM 2)
bool Ith::parseHookCode(const QString &code, HookParam *hp, bool verbose)
{
#define HCODE_PREFIX  "/H"
  enum { HCODE_PREFIX_LEN = sizeof(HCODE_PREFIX) -1 }; // 2
  if (!hp || !code.startsWith(HCODE_PREFIX))
    return false;
  if (verbose)
    DOUT("enter: code =" << code);
  else
    DOUT("enter");

  size_t bufsize = qMax(0xFF, code.size() + 1); // in case detail::Convert modify the buffer
  auto buf = new wchar_t[bufsize];
  code.toWCharArray(buf);
  buf[code.size()] = 0;

  bool ret = detail::Parse(buf + HCODE_PREFIX_LEN, *hp);
  delete[] buf;
#ifdef DEBUG
  if (ret && verbose)
    qDebug()
      << "addr:" << hp->address
      << ", text_fun:" << hp->text_fun
      << ", function:"<< hp->function
      << ", hook_len:" << hp->hook_len
      << ", ind:" << hp->index
      << ", length_offset:" << hp->length_offset
      << ", module:" << hp->module
      << ", off:" <<hp->offset
      << ", recover_len:" << hp->recover_len
      << ", split:" << hp->split
      << ", split_ind:" << hp->split_index
      << ", type:" << hp->type;
#endif // DEBUG
  DOUT("leave: ret =" << ret);
  return ret;
#undef HOOK_CODE_PREFIX
}

bool Ith::verifyHookCode(const QString &code)
{
  HookParam hp = {};
  return parseHookCode(code, &hp);
}

// EOF

// pipe.cc
// 8/24/2013 jichi
// Branch IHF/pipe.cpp, rev 93
// 8/24/2013 TODO: Clean up this file

#include "srv_p.h"
#include "hookman.h"
#include "ith/common/defs.h"
#include "ith/common/const.h"
//#include "ith/common/growl.h"
#include "ith/sys/sys.h"
//#include "CommandQueue.h"

//DWORD WINAPI UpdateWindows(LPVOID lpThreadParameter);

namespace { // unnamed
enum NamedPipeCommand {
  NAMED_PIPE_DISCONNECT = 1
  , NAMED_PIPE_CONNECT = 2
};

bool newline = false;
bool detach = false;

// jichi 10/27/2013
// Check if text has leading space
enum { _filter_limit = 0x20 }; // The same as the orignal ITH filter. So, I don't have to check \u3000
//enum { _filter_limit = 0x19 };
inline bool has_leading_space(const BYTE *text, int len)
{
  return len == 1 ? *text <= _filter_limit : // 1 byte
                    *reinterpret_cast<const WORD *>(text) <= _filter_limit; // 2 bytes
}

// jichi 9/28/2013: Skip leading garbage
// Note:
// - Modifying limit will break manual translation. The orignal one is 0x20
// - Eliminating 0x20 will break English-translated games
const BYTE *Filter(const BYTE *str, int len)
{
#ifdef ITH_DISABLE_FILTER // jichi 9/28/2013: only for debugging purpose
  return str;
#endif // ITH_DISABLE_FILTER
//  if (len && *str == 0x10) // jichi 9/28/2013: garbage on wine, data link escape, or ^P
//    return nullptr;
  //enum { limit = 0x19 };
  while (true)
    if (len >= 2) {
      if (*(const WORD *)str <= _filter_limit) { // jichi 10/27/2013: two bytes
        str += 2;
        len -= 2;
      } else
        break;
    } else if (*str <= _filter_limit) { // jichi 10/27/2013: 1 byte
      str++;
      len--;
    } else
      break;
  return str;
}
} // unnamed namespace

//WCHAR recv_pipe[] = L"\\??\\pipe\\ITH_PIPE";
//WCHAR command_pipe[] = L"\\??\\pipe\\ITH_COMMAND";
wchar_t recv_pipe[] = ITH_TEXT_PIPE;
wchar_t command_pipe[] = ITH_COMMAND_PIPE;

CRITICAL_SECTION detach_cs; // jichi 9/27/2013: also used in main
//HANDLE hDetachEvent;
extern HANDLE hPipeExist;

void CreateNewPipe()
{
  static DWORD acl[7] = {
      0x1C0002,
      1,
      0x140000,
      GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
      0x101,
      0x1000000,
      0};
  static SECURITY_DESCRIPTOR sd = {1, 0, 4, 0, 0, 0, (PACL)acl};

  HANDLE hTextPipe, hCmdPipe, hThread;
  IO_STATUS_BLOCK ios;
  UNICODE_STRING us;

  OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, &us, OBJ_CASE_INSENSITIVE, &sd, 0};
  LARGE_INTEGER time = {-500000, -1};

  RtlInitUnicodeString(&us, recv_pipe);
  if (!NT_SUCCESS(NtCreateNamedPipeFile(
      &hTextPipe,
      GENERIC_READ | SYNCHRONIZE,
      &oa,
      &ios,
      FILE_SHARE_WRITE,
      FILE_OPEN_IF,
      FILE_SYNCHRONOUS_IO_NONALERT,
      1, 1, 0, -1,
      0x1000,
      0x1000,
      &time))) {
    //ConsoleOutput(ErrorCreatePipe);
    ConsoleOutput("vnrhost:CreateNewPipe: failed to create recv pipe");
    return;
  }

  RtlInitUnicodeString(&us, command_pipe);
  if (!NT_SUCCESS(NtCreateNamedPipeFile(
      &hCmdPipe,
      GENERIC_WRITE | SYNCHRONIZE,
      &oa,
      &ios,
      FILE_SHARE_READ,
      FILE_OPEN_IF,
      FILE_SYNCHRONOUS_IO_NONALERT,
      1, 1, 0, -1,
      0x1000,
      0x1000,
      &time))) {
    //ConsoleOutput(ErrorCreatePipe);
    ConsoleOutput("vnrhost:CreateNewPipe: failed to create cmd pipe");
    return;
  }

  hThread = IthCreateThread(RecvThread, (DWORD)hTextPipe);
  man->RegisterPipe(hTextPipe, hCmdPipe, hThread);
}

void DetachFromProcess(DWORD pid)
{
  HANDLE hMutex = INVALID_HANDLE_VALUE,
         hEvent = INVALID_HANDLE_VALUE;
  //try {
  IO_STATUS_BLOCK ios;
  ProcessRecord *pr = man->GetProcessRecord(pid);
  if (!pr)
    return;
  //IthBreak();
  hEvent = IthCreateEvent(nullptr);
  if (STATUS_PENDING == NtFsControlFile(
      man->GetCmdHandleByPID(pid),
      hEvent,
      0,0,
      &ios,
      CTL_CODE(FILE_DEVICE_NAMED_PIPE, NAMED_PIPE_DISCONNECT, 0, 0),
      0,0,0,0))
    NtWaitForSingleObject(hEvent, 0, 0);
  NtClose(hEvent);
  //hEvent = INVALID_HANDLE_VALUE;

  WCHAR mutex[0x20];
  swprintf(mutex, ITH_DETACH_MUTEX_ L"%d", pid);
  hMutex = IthOpenMutex(mutex);
  if (hMutex != INVALID_HANDLE_VALUE) {
    NtWaitForSingleObject(hMutex, 0, 0);
    NtReleaseMutant(hMutex, 0);
    NtClose(hMutex);
    //hMutex = INVALID_HANDLE_VALUE;
  }

  //} catch (...) {
  //  if (hEvent != INVALID_HANDLE_VALUE)
  //    NtClose(hEvent);
  //  else if (hMutex != INVALID_HANDLE_VALUE) {
  //    NtWaitForSingleObject(hMutex, 0, 0);
  //    NtReleaseMutant(hMutex, 0);
  //    NtClose(hMutex);
  //  }
  //}

  //NtSetEvent(hDetachEvent, 0);
  if (::running)
    NtSetEvent(hPipeExist, 0);
}

// jichi 9/27/2013: I don't need this
//void OutputDWORD(DWORD d)
//{
//  WCHAR str[0x20];
//  swprintf(str, L"%.8X", d);
//  ConsoleOutput(str);
//}

DWORD WINAPI RecvThread(LPVOID lpThreadParameter)
{
  HANDLE hTextPipe = (HANDLE)lpThreadParameter;

  IO_STATUS_BLOCK ios;
  NtFsControlFile(hTextPipe,
     0, 0, 0,
     &ios,
     CTL_CODE(FILE_DEVICE_NAMED_PIPE, NAMED_PIPE_CONNECT, 0, 0),
     0, 0, 0, 0);
  if (!::running) {
    NtClose(hTextPipe);
    return 0;
  }

  BYTE *buff;

  enum { PipeBufferSize = 0x1000 };
  buff = new BYTE[PipeBufferSize];
  ITH_MEMSET_HEAP(buff, 0, PipeBufferSize); // jichi 8/27/2013: zero memory, or it will crash wine on start up

  // 10/19/2014 jichi: there are totally three words received
  // See: hook/rpc/pipe.cc
  // struct {
  //   DWORD pid;
  //   TextHook *man;
  //   DWORD module;
  //   //DWORD engine;
  // } u;
  enum { module_struct_size = 12 };
  NtReadFile(hTextPipe, 0, 0, 0, &ios, buff, module_struct_size, 0, 0);

  DWORD pid = *(DWORD *)buff,
        hookman = *(DWORD *)(buff + 0x4),
        module = *(DWORD *)(buff + 0x8);
        //engine = *(DWORD *)(buff + 0xc);
  man->RegisterProcess(pid, hookman, module);

  // jichi 9/27/2013: why recursion?
  CreateNewPipe();

  //NtClose(IthCreateThread(UpdateWindows,0));
  while (::running) {
    if (!NT_SUCCESS(NtReadFile(hTextPipe,
        0, 0, 0,
        &ios,
        buff,
        0xf80,
        0, 0)))
      break;

    enum { data_offset = 0xc }; // jichi 10/27/2013: Seem to be the data offset in the pipe

    DWORD RecvLen = ios.uInformation;
    if (RecvLen < data_offset)
      break;
    DWORD hook = *(DWORD *)buff;

    union { DWORD retn; DWORD cmd_type; };
    union { DWORD split; DWORD new_engine_type; };

    retn = *(DWORD *)(buff + 4);
    split = *(DWORD *)(buff + 8);

    buff[RecvLen] = 0;
    buff[RecvLen + 1] = 0;

    if (hook == IHF_NOTIFICATION) {
      switch (cmd_type) {
      case IHF_NOTIFICATION_NEWHOOK:
        {
          static long lock;
          while (InterlockedExchange(&lock, 1) == 1);
          ProcessEventCallback new_hook = man->ProcessNewHook();
          if (new_hook)
            new_hook(pid);
          lock = 0;
        } break;
      case IHF_NOTIFICATION_TEXT:
        ConsoleOutput((LPCSTR)(buff + 8));
        break;
      }
    } else {
      // jichi 9/28/2013: Debug raw data
      //ITH_DEBUG_DWORD9(RecvLen - 0xc,
      //    buff[0xc], buff[0xd], buff[0xe], buff[0xf],
      //    buff[0x10], buff[0x11], buff[0x12], buff[0x13]);

      const BYTE *data = buff + data_offset; // th
      int len = RecvLen - data_offset;
      bool space = ::has_leading_space(data, len);
      if (space) {
        const BYTE *it = ::Filter(data, len);
        len -= it - data;
        data = it;
      }
      if (len >> 31) // jichi 10/27/2013: len is too large, which seldom happens
        len = 0;
      //man->DispatchText(pid, len ? data : nullptr, hook, retn, split, len, space);
      man->DispatchText(pid, data, hook, retn, split, len, space);
    }
  }

  EnterCriticalSection(&detach_cs);

  HANDLE hDisconnect = IthCreateEvent(nullptr);

  if (STATUS_PENDING == NtFsControlFile(
      hTextPipe,
      hDisconnect,
      0, 0,
      &ios,
      CTL_CODE(FILE_DEVICE_NAMED_PIPE, NAMED_PIPE_DISCONNECT, 0, 0),
      0, 0, 0, 0))
    NtWaitForSingleObject(hDisconnect, 0, 0);

  NtClose(hDisconnect);
  DetachFromProcess(pid);
  man->UnRegisterProcess(pid);

  //NtClearEvent(hDetachEvent);

  LeaveCriticalSection(&detach_cs);
  delete[] buff;

  if (::running)
    ConsoleOutput("vnrhost:DetachFromProcess: detached");

  //if (::running) {
  //  swprintf((LPWSTR)buff, FormatDetach, pid);
  //  ConsoleOutput((LPWSTR)buff);
  //  NtClose(IthCreateThread(UpdateWindows, 0));
  //}
  return 0;
}

// EOF

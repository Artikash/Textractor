// pipe.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/pipe.cpp, rev 66
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
#endif // _MSC_VER

#include "cli.h"
#include "engine/match.h"
#include "ith/common/defs.h"
//#include "ith/common/growl.h"
#include "ith/sys/sys.h"
#include "ccutil/ccmacro.h"

//#include <ITH\AVL.h>
//#include <ITH\ntdll.h>
WCHAR mutex[] = ITH_GRANTPIPE_MUTEX;
WCHAR exist[] = ITH_PIPEEXISTS_EVENT;
WCHAR detach_mutex[0x20];
//WCHAR write_event[0x20];
//WCHAR engine_event[0x20];

//WCHAR recv_pipe[] = L"\\??\\pipe\\ITH_PIPE";
//WCHAR command[] = L"\\??\\pipe\\ITH_COMMAND";
wchar_t recv_pipe[] = ITH_TEXT_PIPE;
wchar_t command[] = ITH_COMMAND_PIPE;

LARGE_INTEGER wait_time = {-100*10000, -1};
LARGE_INTEGER sleep_time = {-20*10000, -1};

DWORD engine_type;
DWORD module_base;

//DWORD engine_base;
bool engine_registered; // 10/19/2014 jichi: disable engine dll

HANDLE hPipe,
       hCommand,
       hDetach; //,hLose;
//InsertHookFun InsertHook;
//IdentifyEngineFun IdentifyEngine;
//InsertDynamicHookFun InsertDynamicHook;

bool hook_inserted = false;

// jichi 9/28/2013: protect pipe on wine
// Put the definition in this file so that it might be inlined
void CliUnlockPipe()
{
  if (IthIsWine())
    IthReleaseMutex(::hmMutex);
}

void CliLockPipe()
{
  if (IthIsWine()) {
    const LONGLONG timeout = -50000000; // in nanoseconds = 5 seconds
    NtWaitForSingleObject(hmMutex, 0, (PLARGE_INTEGER)&timeout);
  }
}

HANDLE IthOpenPipe(LPWSTR name, ACCESS_MASK direction)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us,name);
  SECURITY_DESCRIPTOR sd = {1};
  OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, &us, OBJ_CASE_INSENSITIVE, &sd, 0};
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  if (NT_SUCCESS(NtCreateFile(&hFile, direction, &oa, &isb, 0, 0, FILE_SHARE_READ, FILE_OPEN, 0, 0, 0)))
    return hFile;
  else
    return INVALID_HANDLE_VALUE;
}

DWORD WINAPI WaitForPipe(LPVOID lpThreadParameter) // Dynamically detect ITH main module status.
{
  CC_UNUSED(lpThreadParameter);
  int i;
  TextHook *man;
  struct {
    DWORD pid;
    TextHook *man;
    DWORD module;
    //DWORD engine;
  } u;
  HANDLE hMutex,
         hPipeExist;
  //swprintf(engine_event,L"ITH_ENGINE_%d",current_process_id);
  swprintf(detach_mutex, ITH_DETACH_MUTEX_ L"%d", current_process_id);
  //swprintf(lose_event,L"ITH_LOSEPIPE_%d",current_process_id);
  //hEngine=IthCreateEvent(engine_event);
  //NtWaitForSingleObject(hEngine,0,0);
  //NtClose(hEngine);
  while (!engine_registered)
    NtDelayExecution(0, &wait_time);
  //LoadEngine(L"ITH_Engine.dll");
  u.module = module_base;
  u.pid = current_process_id;
  u.man = hookman;
  //u.engine = engine_base; // jichi 10/19/2014: disable the second dll
  hPipeExist = IthOpenEvent(exist);
  IO_STATUS_BLOCK ios;
  //hLose=IthCreateEvent(lose_event,0,0);
  if (hPipeExist != INVALID_HANDLE_VALUE)
  while (running) {
    hPipe = INVALID_HANDLE_VALUE;
    hCommand = INVALID_HANDLE_VALUE;
    while (NtWaitForSingleObject(hPipeExist,0,&wait_time) == WAIT_TIMEOUT)
      if (!running)
        goto _release;
    hMutex = IthCreateMutex(mutex,0);
    NtWaitForSingleObject(hMutex,0,0);
    while (hPipe == INVALID_HANDLE_VALUE||
      hCommand == INVALID_HANDLE_VALUE) {
      NtDelayExecution(0, &sleep_time);
      if (hPipe == INVALID_HANDLE_VALUE)
        hPipe = IthOpenPipe(recv_pipe, GENERIC_WRITE);
      if (hCommand == INVALID_HANDLE_VALUE)
        hCommand = IthOpenPipe(command, GENERIC_READ);
    }
    //NtClearEvent(hLose);
    CliLockPipe();
    NtWriteFile(hPipe, 0, 0, 0, &ios, &u, sizeof(u), 0, 0);
    CliUnlockPipe();
    live = true;
    for (man = hookman, i = 0; i < current_hook; man++)
      if (man->RecoverHook()) // jichi 9/27/2013: This is the place where built-in hooks like TextOutA are inserted
        i++;
    //ConsoleOutput(dll_name);
    ConsoleOutput("vnrcli:WaitForPipe: pipe connected");
    //OutputDWORD(tree->Count());
    NtReleaseMutant(hMutex,0);
    NtClose(hMutex);
    if (!hook_inserted && engine_registered) {
      hook_inserted = true;
      Engine::IdentifyEngine();
    }
    hDetach = IthCreateMutex(detach_mutex,1);
    while (running && NtWaitForSingleObject(hPipeExist, 0, &sleep_time) == WAIT_OBJECT_0)
      NtDelayExecution(0, &sleep_time);
    live = false;
    for (man = hookman, i = 0; i < current_hook; man++)
      if (man->RemoveHook())
        i++;
    if (!running) {
      IthCoolDown(); // jichi 9/28/2013: Use cooldown instead of lock pipe to prevent from hanging on exit
      //CliLockPipe();
      NtWriteFile(hPipe, 0, 0, 0, &ios, man, 4, 0, 0);
      //CliUnlockPipe();
      IthReleaseMutex(hDetach);
    }
    NtClose(hDetach);
    NtClose(hPipe);
  }
_release:
  //NtClose(hLose);
  NtClose(hPipeExist);
  return 0;
}
DWORD WINAPI CommandPipe(LPVOID lpThreadParameter)
{
  CC_UNUSED(lpThreadParameter);
  DWORD command;
  BYTE buff[0x400] = {};
  HANDLE hPipeExist;
  hPipeExist = IthOpenEvent(exist);
  IO_STATUS_BLOCK ios={};
  if (hPipeExist!=INVALID_HANDLE_VALUE)
    while (running) {
      while (!live) {
        if (!running)
          goto _detach;
        NtDelayExecution(0, &sleep_time);
      }
      // jichi 9/27/2013: Why 0x200 not 0x400? wchar_t?
      switch (NtReadFile(hCommand, 0, 0, 0, &ios, buff, 0x200, 0, 0)) {
      case STATUS_PIPE_BROKEN:
      case STATUS_PIPE_DISCONNECTED:
        NtClearEvent(hPipeExist);
        continue;
      case STATUS_PENDING:
        NtWaitForSingleObject(hCommand, 0, 0);
        switch (ios.Status) {
        case STATUS_PIPE_BROKEN:
        case STATUS_PIPE_DISCONNECTED:
          NtClearEvent(hPipeExist);
          continue;
        case 0: break;
        default:
          if (NtWaitForSingleObject(hDetach, 0, &wait_time) == WAIT_OBJECT_0)
            goto _detach;
        }
      }
      if (ios.uInformation && live) {
        command = *(DWORD *)buff;
        switch(command) {
        case IHF_COMMAND_NEW_HOOK:
          //IthBreak();
          buff[ios.uInformation] = 0;
          buff[ios.uInformation + 1] = 0;
          NewHook(*(HookParam *)(buff + 4), (LPWSTR)(buff + 4 + sizeof(HookParam)), 0);
          break;
        case IHF_COMMAND_REMOVE_HOOK:
          {
            DWORD rm_addr = *(DWORD *)(buff+4);
            HANDLE hRemoved = IthOpenEvent(ITH_REMOVEHOOK_EVENT);

            TextHook *in = hookman;
            for (int i = 0; i < current_hook; in++) {
              if (in->Address()) i++;
              if (in->Address() == rm_addr) break;
            }
            if (in->Address())
              in->ClearHook();
            IthSetEvent(hRemoved);
            NtClose(hRemoved);
          } break;
        case IHF_COMMAND_MODIFY_HOOK:
          {
            DWORD rm_addr = *(DWORD *)(buff + 4);
            HANDLE hModify = IthOpenEvent(ITH_MODIFYHOOK_EVENT);
            TextHook *in = hookman;
            for (int i = 0; i < current_hook; in++) {
              if (in->Address())
                i++;
              if (in->Address() == rm_addr)
                break;
            }
            if (in->Address())
              in->ModifyHook(*(HookParam *)(buff + 4));
            IthSetEvent(hModify);
            NtClose(hModify);
          } break;
        case IHF_COMMAND_DETACH:
          running = false;
          live = false;
          goto _detach;
        default: ;
        }
      }
    }
_detach:
  NtClose(hPipeExist);
  NtClose(hCommand);
  return 0;
}
//extern "C" {
void IHFAPI ConsoleOutput(LPCSTR text)
{ // jichi 12/25/2013: Rewrite the implementation
  if (!live || !text)
    return;
  enum { buf_size = 0x50 };
  BYTE buf[buf_size]; // buffer is needed to append the message header
  size_t text_size = strlen(text) + 1;
  size_t data_size = text_size + 8;

  BYTE *data = (data_size <= buf_size) ? buf : new BYTE[data_size];
  *(DWORD *)data = IHF_NOTIFICATION; //cmd
  *(DWORD *)(data + 4) = IHF_NOTIFICATION_TEXT; //console
  memcpy(data + 8, text, text_size);

  IO_STATUS_BLOCK ios;
  NtWriteFile(hPipe, 0, 0, 0, &ios, data, data_size, 0, 0);
  if (data != buf)
    delete[] data;
}
  //if (str) {
  //  int t, len, sum;
  //  BYTE buffer[0x80];
  //  BYTE *buff;
  //  len = wcslen(str) << 1;
  //  t = swprintf((LPWSTR)(buffer + 8),L"%d: ",current_process_id) << 1;
  //  sum = len + t + 8;
  //  if (sum > 0x80) {
  //    buff = new BYTE[sum];
  //    memset(buff, 0, sum); // jichi 9/25/2013: zero memory
  //    memcpy(buff + 8, buffer + 8, t);
  //  }
  //  else
  //    buff = buffer;
  //  *(DWORD *)buff = IHF_NOTIFICATION; //cmd
  //  *(DWORD *)(buff + 4) = IHF_NOTIFICATION_TEXT; //console
  //  memcpy(buff + t + 8, str, len);
  //  IO_STATUS_BLOCK ios;
  //  NtWriteFile(hPipe,0,0,0,&ios,buff,sum,0,0);
  //  if (buff != buffer)
  //    delete[] buff;
  //  return len;
  //}

//DWORD IHFAPI OutputDWORD(DWORD d)
//{
//  WCHAR str[0x10];
//  swprintf(str,L"%.8X",d);
//  ConsoleOutput(str);
//  return 0;
//}
//DWORD IHFAPI OutputRegister(DWORD *base)
//{
//  WCHAR str[0x40];
//  swprintf(str,L"EAX:%.8X",base[0]);
//  ConsoleOutput(str);
//  swprintf(str,L"ECX:%.8X",base[-1]);
//  ConsoleOutput(str);
//  swprintf(str,L"EDX:%.8X",base[-2]);
//  ConsoleOutput(str);
//  swprintf(str,L"EBX:%.8X",base[-3]);
//  ConsoleOutput(str);
//  swprintf(str,L"ESP:%.8X",base[-4]);
//  ConsoleOutput(str);
//  swprintf(str,L"EBP:%.8X",base[-5]);
//  ConsoleOutput(str);
//  swprintf(str,L"ESI:%.8X",base[-6]);
//  ConsoleOutput(str);
//  swprintf(str,L"EDI:%.8X",base[-7]);
//  ConsoleOutput(str);
//  return 0;
//}
//DWORD IHFAPI RegisterEngineModule(DWORD idEngine, DWORD dnHook)
//{
//  ::IdentifyEngine = (IdentifyEngineFun)idEngine;
//  ::InsertDynamicHook = (InsertDynamicHookFun)dnHook;
//  ::engine_registered = true;
//  return 0;
//}
DWORD IHFAPI NotifyHookInsert(DWORD addr)
{
  if (live) {
    BYTE buffer[0x10];
    *(DWORD *)buffer = IHF_NOTIFICATION;
    *(DWORD *)(buffer + 4) = IHF_NOTIFICATION_NEWHOOK;
    *(DWORD *)(buffer + 8) = addr;
    *(DWORD *)(buffer + 0xc) = 0;
    IO_STATUS_BLOCK ios;
    CliLockPipe();
    NtWriteFile(hPipe,0,0,0,&ios,buffer,0x10,0,0);
    CliUnlockPipe();
  }
  return 0;
}
//} // extern "C"

// EOF

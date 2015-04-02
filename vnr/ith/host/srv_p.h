#pragma once
// srv_p.h
// 8/24/2013 jichi
// Branch IHF/main.h, rev 111
#include "config.h"

#define GLOBAL extern
#define SHIFT_JIS 0x3A4
class HookManager;
//class CommandQueue;
class SettingManager;
class TextHook;
//class BitMap;
//class CustomFilterMultiByte;
//class CustomFilterUnicode;
//#define TextHook Hook
GLOBAL BOOL running;
//GLOBAL BitMap *pid_map;
//GLOBAL CustomFilterMultiByte *mb_filter;
//GLOBAL CustomFilterUnicode *uni_filter;
GLOBAL HookManager *man;
//GLOBAL CommandQueue *cmdq;
GLOBAL SettingManager *setman;
GLOBAL WCHAR recv_pipe[];
GLOBAL WCHAR command[];
GLOBAL HANDLE hPipeExist;
GLOBAL DWORD split_time,
             cyclic_remove,
             clipboard_flag,
             global_filter;
GLOBAL CRITICAL_SECTION detach_cs;

DWORD WINAPI RecvThread(LPVOID lpThreadParameter);
DWORD WINAPI CmdThread(LPVOID lpThreadParameter);

void ConsoleOutput(LPCSTR text);
void ConsoleOutputW(LPCWSTR text);
DWORD  GetCurrentPID();
//DWORD  GetProcessIDByPath(LPWSTR str);
HANDLE  GetCmdHandleByPID(DWORD pid);
//DWORD  Inject(HANDLE hProc);
//DWORD  InjectByPID(DWORD pid);
//DWORD  PIDByName(LPWSTR target);
//DWORD  Hash(LPCWSTR module, int length=-1);

// EOF

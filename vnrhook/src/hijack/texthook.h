#pragma once

// texthook.h
// 8/24/2013 jichi
// Branch: IHF_DLL/IHF_CLIENT.h, rev 133
//
// 8/24/2013 TODO:
// - Clean up this file
// - Reduce global variables. Use namespaces or singleton classes instead.
#include <string>
#include <unordered_map>
#include "include/types.h"
#include <windows.h>

extern int currentHook;
extern WCHAR dll_mutex[];
//extern WCHAR dll_name[];
extern DWORD trigger;
//extern DWORD current_process_id;

// jichi 6/3/2014: Get memory range of the current module
extern DWORD processStartAddress,
             processStopAddress;

void InitFilterTable();

// jichi 9/25/2013: This class will be used by NtMapViewOfSectionfor
// interprocedure communication, where constructor/destructor will NOT work.
class TextHook : public Hook
{
  int InsertHookCode();
  int InsertReadCode();
  int UnsafeInsertHookCode();
  DWORD UnsafeSend(DWORD dwDataBase, DWORD dwRetn);
  int RemoveHookCode();
  int RemoveReadCode();
  int SetHookName(LPCSTR name);
public:
  int InsertHook();
  int InitHook(const HookParam &hp, LPCSTR name = 0, WORD set_flag = 0);
  DWORD Send(DWORD dwDataBase, DWORD dwRetn);
  int ClearHook();
  int GetLength(DWORD base, DWORD in); // jichi 12/25/2013: Return 0 if failed
};

extern TextHook *hookman,
                *current_available;

//void InitDefaultHook();

struct FilterRange { DWORD lower, upper; };
extern FilterRange *filter;

extern bool running,
            live;

extern HANDLE hookPipe,
              hmMutex;

DWORD WINAPI WaitForPipe(LPVOID lpThreadParameter);
DWORD WINAPI CommandPipe(LPVOID lpThreadParameter);
DWORD WINAPI PipeManager(LPVOID unused);

//void RequestRefreshProfile();

//typedef DWORD (*InsertHookFun)(DWORD);
//typedef DWORD (*IdentifyEngineFun)();
//typedef DWORD (*InsertDynamicHookFun)(LPVOID addr, DWORD frame, DWORD stack);
//extern IdentifyEngineFun IdentifyEngine;
//extern InsertDynamicHookFun InsertDynamicHook;

// jichi 9/28/2013: Protect pipeline in wine
void CliLockPipe();
void CliUnlockPipe();

enum : int { yes = 0, no = 1 };

// EOF

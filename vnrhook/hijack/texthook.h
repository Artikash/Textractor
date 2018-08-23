#pragma once

// texthook.h
// 8/24/2013 jichi
// Branch: IHF_DLL/IHF_CLIENT.h, rev 133
//
// 8/24/2013 TODO:
// - Clean up this file
// - Reduce global variables. Use namespaces or singleton classes instead.
#include "common.h"
#include "pipe.h"

extern int currentHook;
extern DWORD trigger;

// jichi 9/25/2013: This class will be used by NtMapViewOfSectionfor
// interprocedure communication, where constructor/destructor will NOT work.

class TextHook
{
	int InsertHookCode();
	int InsertReadCode();
	int UnsafeInsertHookCode();
	DWORD UnsafeSend(DWORD dwDataBase, DWORD dwRetn);
	int RemoveHookCode();
	int RemoveReadCode();
	int SetHookName(LPCSTR name);
public:
	HookParam hp;
	LPSTR hook_name;
	int name_length;
	BYTE recover[0x68 - sizeof(HookParam)];
	BYTE original[0x10];

	unsigned __int64 Address() const { return hp.address; }
	DWORD Type() const { return hp.type; }
	WORD Length() const { return hp.hook_len; }
	LPSTR Name() const { return hook_name; }
	int NameLength() const { return name_length; }
	int InsertHook();
	int InitHook(const HookParam &hp, LPCSTR name = 0, WORD set_flag = 0);
	DWORD Send(DWORD dwDataBase, DWORD dwRetn);
	int ClearHook();
	int GetLength(DWORD base, DWORD in); // jichi 12/25/2013: Return 0 if failed
};

// jichi 1/16/2015: Though called max hook, it means max number of text threads
enum { MAX_HOOK = 64 };
enum { HOOK_SECTION_SIZE = MAX_HOOK * sizeof(TextHook) * 2, HOOK_BUFFER_SIZE = MAX_HOOK * sizeof(TextHook) };

extern TextHook *hookman,
*current_available;

extern bool running,
live;

extern HANDLE hookPipe,
hmMutex;

DWORD WINAPI PipeManager(LPVOID unused);

enum : int { yes = 0, no = 1 };

// EOF

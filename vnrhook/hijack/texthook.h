#pragma once

// texthook.h
// 8/24/2013 jichi
// Branch: IHF_DLL/IHF_CLIENT.h, rev 133
//
// 8/24/2013 TODO:
// - Clean up this file
// - Reduce global variables. Use namespaces or singleton classes instead.
#include "common.h"
#include "types.h"

extern int currentHook;
extern DWORD trigger;

// jichi 9/25/2013: This class will be used by NtMapViewOfSectionfor
// interprocedure communication, where constructor/destructor will NOT work.

class TextHook
{
	bool InsertHookCode();
	bool InsertReadCode();
	bool UnsafeInsertHookCode();
	DWORD UnsafeSend(DWORD dwDataBase, DWORD dwRetn);
	void RemoveHookCode();
	void RemoveReadCode();
	void SetHookName(LPCSTR name);
public:
	HookParam hp;
	LPSTR hook_name;
	int name_length;
	BYTE trampoline[120];
	HANDLE readerHandle;

	bool InsertHook();
	void InitHook(const HookParam &hp, LPCSTR name = 0, WORD set_flag = 0);
	DWORD Send(DWORD dwDataBase, DWORD dwRetn);
	void ClearHook();
	int GetLength(DWORD base, DWORD in); // jichi 12/25/2013: Return 0 if failed
};

enum { MAX_HOOK = 300 };
enum { HOOK_SECTION_SIZE = MAX_HOOK * sizeof(TextHook) * 2, HOOK_BUFFER_SIZE = MAX_HOOK * sizeof(TextHook) };

extern TextHook *hookman;

extern bool running;

extern HANDLE hookPipe, hmMutex;

// EOF

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

void SetTrigger();

// jichi 9/25/2013: This class will be used by NtMapViewOfSectionfor
// interprocedure communication, where constructor/destructor will NOT work.

class TextHook
{
	bool InsertHookCode();
	bool InsertReadCode();
	int GetLength(DWORD base, DWORD in); // jichi 12/25/2013: Return 0 if failed
	void RemoveHookCode();
	void RemoveReadCode();

public:
	HookParam hp;
	char hookName[HOOK_NAME_SIZE];
	BYTE trampoline[120];
	HANDLE readerHandle;

	bool InsertHook();
	void InitHook(HookParam hp, LPCSTR name, DWORD set_flag);
	void Send(DWORD dwDataBase);
	void ClearHook();
};

enum { MAX_HOOK = 300, HOOK_BUFFER_SIZE = MAX_HOOK * sizeof(TextHook), HOOK_SECTION_SIZE = HOOK_BUFFER_SIZE * 2 };

// EOF

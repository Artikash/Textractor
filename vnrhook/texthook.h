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
public:
	HookParam hp;
	union
	{
		uint64_t address;
		void* location;
	}; // Absolute address

	bool Insert(HookParam hp, DWORD set_flag);
	void Clear();

private:
	static DWORD WINAPI Reader(LPVOID hookPtr);
	bool InsertHookCode();
	bool InsertReadCode();
	void Send(uintptr_t dwDatabase);
	int GetLength(uintptr_t base, uintptr_t in); // jichi 12/25/2013: Return 0 if failed
	void RemoveHookCode();
	void RemoveReadCode();

	HANDLE readerThread, readerEvent;
	bool err;
	BYTE trampoline[130];

};

enum { MAX_HOOK = 300, HOOK_BUFFER_SIZE = MAX_HOOK * sizeof(TextHook), HOOK_SECTION_SIZE = HOOK_BUFFER_SIZE * 2 };

// EOF

#pragma once

// main.h
// 8/23/2013 jichi
// Branch: ITH/IHF_DLL.h, rev 66

#include "common.h"
#include "types.h"

void TextOutput(ThreadParam tp, BYTE* text, int len);
void ConsoleOutput(LPCSTR text, ...);
void NotifyHookRemove(uint64_t addr);
void NewHook(HookParam hp, LPCSTR name, DWORD flag = HOOK_ENGINE);
void RemoveHook(uint64_t addr, int maxOffset = 9);

extern "C" // minhook library
{
	enum MH_STATUS
	{
		MH_OK,
		MH_ERROR_ALREADY_INITIALIZED,
		MH_ERROR_NOT_INITIALIZED,
		MH_ERROR_ALREADY_CREATED,
		MH_ERROR_NOT_CREATED,
		MH_ERROR_ENABLED,
		MH_ERROR_DISABLED,
		MH_ERROR_NOT_EXECUTABLE,
		MH_ERROR_UNSUPPORTED_FUNCTION,
		MH_ERROR_MEMORY_ALLOC,
		MH_ERROR_MEMORY_PROTECT,
		MH_ERROR_MODULE_NOT_FOUND,
		MH_ERROR_FUNCTION_NOT_FOUND
	};

	MH_STATUS WINAPI MH_Initialize(VOID);
	MH_STATUS WINAPI MH_Uninitialize(VOID);

	// Creates a Hook for the specified target function, in disabled state.
	// Parameters:
	//   pTarget    [in]  A pointer to the target function, which will be
	//                    overridden by the detour function.
	//   pDetour    [in]  A pointer to the detour function, which will override
	//                    the target function.
	//   ppOriginal [out] A pointer to the trampoline function, which will be
	//                    used to call the original target function.
	//                    This parameter can be NULL.
	MH_STATUS WINAPI MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal);
	MH_STATUS WINAPI MH_EnableHook(LPVOID pTarget);
	MH_STATUS WINAPI MH_DisableHook(LPVOID pTarget);
	MH_STATUS WINAPI MH_RemoveHook(LPVOID pTarget);
	const char* WINAPI MH_StatusToString(MH_STATUS status);
}

#define ITH_RAISE  (*(int*)0 = 0) // raise C000005, for debugging only
#define ITH_TRY    __try
#define ITH_EXCEPT __except(EXCEPTION_EXECUTE_HANDLER)
#define ITH_WITH_SEH(...) ITH_TRY { __VA_ARGS__; } ITH_EXCEPT {}

// EOF

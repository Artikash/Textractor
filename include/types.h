#pragma once

#include "common.h"
#include "const.h"

// jichi 3/7/2014: Add guessed comment
struct HookParam 
{
	// jichi 8/24/2013: For special hooks.
	typedef void(*text_fun_t)(DWORD esp, HookParam *hp, BYTE index, DWORD *data, DWORD *split, DWORD *len);
	typedef bool(*filter_fun_t)(LPVOID str, DWORD *len, HookParam *hp, BYTE index); // jichi 10/24/2014: Add filter function. Return true if skip the text
	typedef bool(*hook_fun_t)(DWORD esp, HookParam *hp); // jichi 10/24/2014: Add generic hook function, return false if stop execution.

	uint64_t insertion_address; // absolute address
	uint64_t address; // absolute or relative address (not changed by TextHook)
	int offset, // offset of the data in the memory
		index, // deref_offset1
		split, // offset of the split character
		split_index; // deref_offset2
	wchar_t module[MAX_MODULE_SIZE];
	char function[MAX_MODULE_SIZE];
	DWORD type; // flags
	UINT codepage; // text encoding
	WORD length_offset; // index of the string length
	DWORD user_value; // 7/20/2014: jichi additional parameters for PSP games

	text_fun_t text_fun;
	filter_fun_t filter_fun;
	hook_fun_t hook_fun;
};

struct ThreadParam
{
	DWORD processId;
	uint64_t addr;
	uint64_t ctx; // The context of the hook: by default the first value on stack, usually the return address
	uint64_t ctx2;  // The subcontext of the hook: 0 by default, generated in a method specific to the hook
};
// Artikash 5/31/2018: required for unordered_map to work with struct key
template <> struct std::hash<ThreadParam> { size_t operator()(const ThreadParam& tp) const { return std::hash<int64_t>()((tp.processId + tp.addr) ^ (tp.ctx + tp.ctx2)); } };
static bool operator==(const ThreadParam& one, const ThreadParam& two) { return one.processId == two.processId && one.addr == two.addr && one.ctx == two.ctx && one.ctx2 == two.ctx2; }

class WinMutex
{
	HANDLE mutex;
public:
	WinMutex(std::wstring name) : mutex(CreateMutexW(nullptr, false, name.c_str())) {}
	~WinMutex() { ReleaseMutex(mutex); CloseHandle(mutex); }
	void lock() { WaitForSingleObject(mutex, 0); }
	void unlock() { ReleaseMutex(mutex); }
};

struct InsertHookCmd // From host
{
	InsertHookCmd(HookParam hp, std::string name = "") : hp(hp) { strcpy_s<HOOK_NAME_SIZE>(this->name, name.c_str()); };
	int command = HOST_COMMAND_NEW_HOOK;
	HookParam hp;
	char name[HOOK_NAME_SIZE] = {};
};

struct RemoveHookCmd // From host
{
	RemoveHookCmd(uint64_t address) : address(address) {};
	int command = HOST_COMMAND_REMOVE_HOOK;
	uint64_t address;
};

struct ConsoleOutputNotif // From hook
{
	ConsoleOutputNotif(std::string message = "") { strcpy_s<MESSAGE_SIZE>(this->message, message.c_str()); };
	int command = HOST_NOTIFICATION_TEXT;
	char message[MESSAGE_SIZE] = {};
};

struct HookRemovedNotif // From hook
{
	HookRemovedNotif(uint64_t address) : address(address) {};
	int command = HOST_NOTIFICATION_RMVHOOK;
	uint64_t address;
};

#define LOCK(mutex) std::lock_guard lock(mutex)

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

struct ThreadParam // From hook, used internally by host as well
{
	DWORD pid; // jichi: 5/11/2014: The process ID
	uint64_t hook; // Artikash 6/6/2018: The insertion address of the hook
	uint64_t retn; // jichi 5/11/2014: The return address of the hook
	uint64_t spl;  // jichi 5/11/2014: the processed split value of the hook paramete
};
// Artikash 5/31/2018: required for unordered_map to work with struct key
template <> struct std::hash<ThreadParam> { size_t operator()(const ThreadParam& tp) const { return std::hash<int64_t>()((tp.pid + tp.hook) ^ (tp.retn + tp.spl)); } };
static bool operator==(const ThreadParam& one, const ThreadParam& two) { return one.pid == two.pid && one.hook == two.hook && one.retn == two.retn && one.spl == two.spl; }

struct InsertHookCmd // From host
{
	InsertHookCmd(HookParam hp, std::string name = "") : hp(hp) { strcpy_s<MESSAGE_SIZE>(this->name, name.c_str()); };
	int command = HOST_COMMAND_NEW_HOOK;
	HookParam hp;
	char name[MESSAGE_SIZE] = {};
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

#define LOCK(mutex) std::lock_guard<std::recursive_mutex> lock(mutex)

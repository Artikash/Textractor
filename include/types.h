#pragma once

#include "common.h"
#include "const.h"

template <typename T> using Array = T[];

template<typename E, typename M = std::mutex, template<typename...> typename P = std::unique_ptr>
class ThreadSafePtr
{
public:
	template <typename ...Args> ThreadSafePtr(Args ...args) : ptr(new E(args...)), mtxPtr(new M) {}
	auto operator->()
	{
		struct
		{
			E* operator->() { return ptr; }
			std::unique_lock<M> lock;
			E* ptr;
		} lockedProxy{ std::unique_lock<M>(*mtxPtr), ptr.get() };
		return lockedProxy;
	}

private:
	P<E> ptr;
	P<M> mtxPtr;
};

struct DefHandleCloser { void operator()(void* h) { CloseHandle(h); } };
template <typename HandleCloser = DefHandleCloser>
class AutoHandle
{
public:
	AutoHandle(HANDLE h) : h(h) {}
	operator HANDLE() { return h.get(); }
	operator PHANDLE() { return &h._Myptr(); }
	operator bool() { return h.get() != NULL && h.get() != INVALID_HANDLE_VALUE; }

private:
	struct HandleCleaner : HandleCloser { void operator()(void* h) { if (h != INVALID_HANDLE_VALUE) HandleCloser::operator()(h); } };
	std::unique_ptr<void, HandleCleaner> h;
};

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

	char name[HOOK_NAME_SIZE];
};

struct ThreadParam
{
	DWORD processId;
	uint64_t addr;
	uint64_t ctx; // The context of the hook: by default the first value on stack, usually the return address
	uint64_t ctx2;  // The subcontext of the hook: 0 by default, generated in a method specific to the hook
};
// Artikash 5/31/2018: required for unordered_map to work with struct key
template <> struct std::hash<ThreadParam> { size_t operator()(ThreadParam tp) const { return std::hash<int64_t>()((tp.processId + tp.addr) ^ (tp.ctx + tp.ctx2)); } };
static bool operator==(ThreadParam one, ThreadParam two) { return one.processId == two.processId && one.addr == two.addr && one.ctx == two.ctx && one.ctx2 == two.ctx2; }

class WinMutex // Like CMutex but works with lock_guard
{
public:
	WinMutex(std::wstring name) : m(CreateMutexW(nullptr, FALSE, name.c_str())) {}
	void lock() { if (m) WaitForSingleObject(m, 0); }
	void unlock() { if (m) ReleaseMutex(m); }

private:
	AutoHandle<> m;
};

struct InsertHookCmd // From host
{
	InsertHookCmd(HookParam hp) : hp(hp) {};
	int command = HOST_COMMAND_NEW_HOOK;
	HookParam hp;
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

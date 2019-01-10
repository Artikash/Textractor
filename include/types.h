#pragma once

#include "common.h"
#include "const.h"

template <typename T> using Array = T[];

template <auto F>
struct Functor
{
	template <typename... Args>
	auto operator()(Args&&... args) const { return std::invoke(F, std::forward<Args>(args)...); }
};

template<typename E, typename M = std::mutex>
class ThreadSafe
{
public:
	template <typename... Args> ThreadSafe(Args&&... args) : contents(std::forward<Args>(args)...) {}
	auto operator->()
	{
		struct
		{
			E* operator->() { return ptr; }
			std::unique_lock<M> lock;
			E* ptr;
		} lockedProxy{ std::unique_lock(mtx), &contents };
		return lockedProxy;
	}

private:
	E contents;
	M mtx;
};

template <typename HandleCloser = Functor<CloseHandle>>
class AutoHandle
{
public:
	AutoHandle(HANDLE h) : h(h) {}
	operator HANDLE() { return h.get(); }
	PHANDLE operator&() { return &h._Myptr(); }
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

	uint64_t address; // absolute or relative address
	int offset, // offset of the data in the memory
		index, // deref_offset1
		split, // offset of the split character
		split_index; // deref_offset2
	union
	{
		wchar_t module[MAX_MODULE_SIZE];
		wchar_t text[MAX_MODULE_SIZE];
	};
	char function[MAX_MODULE_SIZE];
	DWORD type; // flags
	UINT codepage; // text encoding
	short length_offset; // index of the string length
	DWORD user_value; // 7/20/2014: jichi additional parameters for PSP games

	text_fun_t text_fun;
	filter_fun_t filter_fun;
	hook_fun_t hook_fun;

	char name[HOOK_NAME_SIZE];
};

struct ThreadParam
{
	bool operator==(ThreadParam other) const { return processId == other.processId && addr == other.addr && ctx == other.ctx && ctx2 == other.ctx2; }
	DWORD processId;
	uint64_t addr;
	uint64_t ctx; // The context of the hook: by default the first value on stack, usually the return address
	uint64_t ctx2;  // The subcontext of the hook: 0 by default, generated in a method specific to the hook
};

class WinMutex // Like CMutex but works with scoped_lock
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
	InsertHookCmd(HookParam hp) : hp(hp) {}
	int command = HOST_COMMAND_NEW_HOOK;
	HookParam hp;
};

struct ConsoleOutputNotif // From hook
{
	ConsoleOutputNotif(std::string message = "") { strcpy_s<MESSAGE_SIZE>(this->message, message.c_str()); }
	int command = HOST_NOTIFICATION_TEXT;
	char message[MESSAGE_SIZE] = {};
};

struct HookRemovedNotif // From hook
{
	HookRemovedNotif(uint64_t address) : address(address) {};
	int command = HOST_NOTIFICATION_RMVHOOK;
	uint64_t address;
};

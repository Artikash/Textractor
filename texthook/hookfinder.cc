#include "hookfinder.h"
#include "defs.h"
#include "main.h"
#include "util.h"

extern const char* STARTING_SEARCH;
extern const char* HOOK_SEARCH_INITIALIZED;
extern const char* HOOK_SEARCH_FINISHED;

extern WinMutex viewMutex;

namespace
{
	constexpr int CACHE_SIZE = 500'000;
	struct HookRecord
	{
		HookRecord() : address(0) {}
		~HookRecord() { if (address) NotifyHookFound(address, offset, text); }
		uint64_t address;
		int offset;
		wchar_t text[200];
	};
	std::unique_ptr<HookRecord[]> records;
	long recordsAvailable;
	uint64_t addressCharCache[CACHE_SIZE] = {};
	long sumCache[CACHE_SIZE] = {};

	DWORD DUMMY;
#ifndef _WIN64
	BYTE trampoline[32] =
	{
		0x9c, // pushfd
		0x60, // pushad
		0x68, 0,0,0,0, // push @addr ; after this a total of 0x28 bytes are pushed
		0x8d, 0x44, 0x24, 0x28, // lea eax,[esp+0x28]
		0x50, // push eax ; stack
		0xbb, 0,0,0,0, // mov ebx,@Send
		0xff, 0xd3, // call ebx
		0x83, 0xc4, 0x08, // add esp, 0x8 ; doesn't matter which register
		0x61, // popad
		0x9d,  // popfd
		0x68, 0,0,0,0, // push @original
		0xc3  // ret ; basically absolute jmp to @original
	};
	constexpr int addr_offset = 3, send_offset = 13, original_offset = 25, registers = 8;
#else
	BYTE trampoline[128] = {
		0x9c, // push rflags
		0x50, // push rax
		0x53, // push rbx
		0x51, // push rcx
		0x52, // push rdx
		0x54, // push rsp
		0x55, // push rbp
		0x56, // push rsi
		0x57, // push rdi
		0x41, 0x50, // push r8
		0x41, 0x51, // push r9
		0x41, 0x52, // push r10
		0x41, 0x53, // push r11
		0x41, 0x54, // push r12
		0x41, 0x55, // push r13
		0x41, 0x56, // push r14
		0x41, 0x57, // push r15
		// https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention
		// https://stackoverflow.com/questions/43358429/save-value-of-xmm-registers
		0x48, 0x83, 0xec, 0x20, // sub rsp,0x20
		0xc5, 0xfa, 0x7f, 0x24, 0x24, // vmovdqu [rsp],xmm4
		0xc5, 0xfa, 0x7f, 0x6c, 0x24, 0x10, // vmovdqu [rsp+0x10],xmm5
		0x48, 0x8d, 0x8c, 0x24, 0xa8, 0x00, 0x00, 0x00, // lea rcx,[rsp+0xa8]
		0x48, 0xba, 0,0,0,0,0,0,0,0, // mov rcx,@addr
		0x48, 0xb8, 0,0,0,0,0,0,0,0, // mov rax,@Send
		0xff, 0xd0, // call rax
		0xc5, 0xfa, 0x6f, 0x6c, 0x24, 0x10, // vmovdqu xmm5,XMMWORD PTR[rsp + 0x10]
		0xc5, 0xfa, 0x6f, 0x24, 0x24, // vmovdqu xmm4,XMMWORD PTR[rsp]
		0x48, 0x83, 0xc4, 0x20, // add rsp,0x20
		0x41, 0x5f, // pop r15
		0x41, 0x5e, // pop r14
		0x41, 0x5d, // pop r13
		0x41, 0x5c, // pop r12
		0x41, 0x5b, // pop r11
		0x41, 0x5a, // pop r10
		0x41, 0x59, // pop r9
		0x41, 0x58, // pop r8
		0x5f, // pop rdi
		0x5e, // pop rsi
		0x5d, // pop rbp
		0x5c, // pop rsp
		0x5a, // pop rdx
		0x59, // pop rcx
		0x5b, // pop rbx
		0x58, // pop rax
		0x9d, // pop rflags
		0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [0] ; relative to next instruction (i.e. jmp @original)
		0,0,0,0,0,0,0,0 // @original
	};
	constexpr int addr_offset = 50, send_offset = 60, original_offset = 116, registers = 16;
#endif
}

void Send(wchar_t** stack, uintptr_t address)
{
	// it is unsafe to call ANY external functions from this, as they may have been hooked (if called the hook would call this function making an infinite loop)
	// the exceptions are compiler intrinsics like _InterlockedDecrement
	if (recordsAvailable <= 0) return;
	for (int i = -registers; i < 6; ++i)
	{
		int length = 0, sum = 0;
		__try { for (wchar_t* str = stack[i]; str[length] && length < 200; ++length) sum += str[length]; }
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		if (length > 7 && length < 199)
		{
			__try
			{
				// many duplicate results with same address and second character will be found: filter them out
				uint64_t addressAndChar = (((uint64_t)stack[i][1]) << 48) | address;
				if (addressCharCache[addressAndChar % CACHE_SIZE] == addressAndChar) continue;
				addressCharCache[addressAndChar % CACHE_SIZE] = addressAndChar;
				// if there are huge amount of strings that are the same, it's probably garbage: filter them out
				// can't store all the strings, so use sum as heuristic instead
				if (_InterlockedIncrement(sumCache + (sum % CACHE_SIZE)) > 25) continue;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}

			long n = _InterlockedDecrement(&recordsAvailable);
			__try
			{
				if (n > 0)
				{
					records[n].address = address;
					records[n].offset = i * sizeof(wchar_t*);
					for (int j = 0; j < length; ++j) records[n].text[j] = stack[i][j];
					records[n].text[length] = 0;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) { records[n].address = 0; }
			
		}
	}
}

void SearchForHooks(SearchParam sp)
{
	std::thread([=]
	{
		static std::mutex m;
		std::scoped_lock lock(m);

		try
		{
			records = std::make_unique<HookRecord[]>(recordsAvailable = CACHE_SIZE);
		}
		catch (std::bad_alloc&) { return ConsoleOutput("Textractor: SearchForHooks ERROR (out of memory)"); }

		uintptr_t moduleStartAddress = (uintptr_t)GetModuleHandleW(ITH_DLL);
		uintptr_t moduleStopAddress = moduleStartAddress;
		MEMORY_BASIC_INFORMATION info;
		do
		{
			VirtualQuery((void*)moduleStopAddress, &info, sizeof(info));
			moduleStopAddress = (uintptr_t)info.BaseAddress + info.RegionSize;
		} while (info.Protect > PAGE_NOACCESS);
		moduleStopAddress -= info.RegionSize;

		ConsoleOutput(STARTING_SEARCH);
		std::vector<uint64_t> addresses = Util::SearchMemory(sp.pattern, sp.length);
		for (auto& addr : addresses) addr += sp.offset;
		addresses.erase(std::remove_if(addresses.begin(), addresses.end(), [&](uint64_t addr)
		{
			return (addr > moduleStartAddress && addr < moduleStopAddress) || addr > sp.maxAddress || addr < sp.minAddress;
		}), addresses.end());
		*(void**)(trampoline + send_offset) = Send;
		auto trampolines = (decltype(trampoline)*)VirtualAlloc(NULL, sizeof(trampoline) * addresses.size(), MEM_COMMIT, PAGE_READWRITE);
		VirtualProtect(trampolines, addresses.size() * sizeof(trampoline), PAGE_EXECUTE_READWRITE, &DUMMY);
		for (int i = 0; i < addresses.size(); ++i)
		{
			void* original;
			MH_CreateHook((void*)addresses[i], trampolines[i], &original);
			MH_QueueEnableHook((void*)addresses[i]);
			memcpy(trampolines[i], trampoline, sizeof(trampoline));
			*(uintptr_t*)(trampolines[i] + addr_offset) = addresses[i];
			*(void**)(trampolines[i] + original_offset) = original;
		}
		ConsoleOutput(HOOK_SEARCH_INITIALIZED, addresses.size());
		MH_ApplyQueued();
		Sleep(sp.searchTime);
		for (auto addr : addresses) MH_QueueDisableHook((void*)addr);
		MH_ApplyQueued();
		Sleep(1000);
		for (auto addr : addresses) MH_RemoveHook((void*)addr);
		records.reset();
		VirtualFree(trampolines, 0, MEM_RELEASE);
		for (int i = 0; i < CACHE_SIZE; ++i) addressCharCache[i] = sumCache[i] = 0;
		ConsoleOutput(HOOK_SEARCH_FINISHED, CACHE_SIZE - recordsAvailable);
	}).detach();
}

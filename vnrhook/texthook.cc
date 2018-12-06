// texthook.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/texthook.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
# pragma warning (disable:4018)   // C4018: sign/unsigned mismatch
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "texthook.h"
#include "MinHook.h"
#include "engine/match.h"
#include "main.h"
#include "const.h"
#include "text.h"
#include "ithsys/ithsys.h"
#include "growl.h"
#include <Psapi.h>

extern std::unique_ptr<WinMutex> viewMutex;

// - Unnamed helpers -

namespace { // unnamed
#ifndef _WIN64

	BYTE common_hook[] = {
	  0x9c, // pushfd
	  0x60, // pushad
	  0x9c, // pushfd ; Artikash 11/4/2018: not sure why pushfd happens twice. Anyway, after this a total of 0x28 bytes are pushed
	  0x8d, 0x44, 0x24, 0x28, // lea eax,[esp+0x28]
	  0x50, // push eax ; dwDatabase
	  0xb9, 0,0,0,0, // mov ecx,@this
	  0xbb, 0,0,0,0, // mov ebx,@TextHook::Send
	  0xff, 0xd3, // call ebx
	  0x9d, // popfd
	  0x61, // popad
	  0x9d,  // popfd
	  0x68, 0,0,0,0, // push @original
	  0xc3  // ret ; basically absolute jmp to @original
	};

#else
	const BYTE common_hook[] = {
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
	0x48, 0x8b, 0xd4, // mov rdx,rsp
	0x48, 0xb9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov rcx, ?? ; pointer to TextHook
	0xff, 0x15, 0x02, 0x0, 0x0, 0x0, 0xeb, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // call TextHook::Send
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
	0xff, 0x25, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 // jmp @original
	};
#endif

	bool trigger = false;
} // unnamed namespace

void SetTrigger()
{
	trigger = true;
}

// - TextHook methods -

bool TextHook::Insert(HookParam h, DWORD set_flag)
{
	LOCK(*viewMutex);
	hp = h;
	hp.insertion_address = hp.address;
	hp.type |= set_flag;
	if (hp.type & USING_UTF8) hp.codepage = CP_UTF8;
	if (hp.type & DIRECT_READ) return InsertReadCode();
#ifndef _WIN64
	else return InsertHookCode();
#endif
	return false;
}

#ifndef _WIN64
// jichi 5/11/2014:
// - dwDataBase: the stack address
void TextHook::Send(DWORD dwDataBase)
{
	__try
	{
		DWORD dwCount,
			dwAddr,
			dwDataIn,
			dwRetn,
			dwSplit;
		BYTE pbData[PIPE_BUFFER_SIZE];
		DWORD dwType = hp.type;

		dwAddr = hp.insertion_address;
		dwRetn = *(DWORD*)dwDataBase; // first value on stack (if hooked start of function, this is return address)

		if (trigger)
			trigger = Engine::InsertDynamicHook((LPVOID)dwAddr, *(DWORD *)(dwDataBase - 0x1c), *(DWORD *)(dwDataBase - 0x18));

		// jichi 10/24/2014: generic hook function
		if (hp.hook_fun && !hp.hook_fun(dwDataBase, &hp))
			hp.hook_fun = nullptr;

		if (dwType & HOOK_EMPTY) return; // jichi 10/24/2014: dummy hook only for dynamic hook

		dwCount = 0;
		dwSplit = 0;
		dwDataIn = *(DWORD *)(dwDataBase + hp.offset); // default value

		if (hp.text_fun) {
			hp.text_fun(dwDataBase, &hp, 0, &dwDataIn, &dwSplit, &dwCount);
		}
		else {
			if (dwDataIn == 0) return;
			if (dwType & FIXING_SPLIT) dwSplit = FIXED_SPLIT_VALUE; // fuse all threads, and prevent floating
			else if (dwType & USING_SPLIT) {
				dwSplit = *(DWORD *)(dwDataBase + hp.split);
				if (dwType & SPLIT_INDIRECT) dwSplit = *(DWORD *)(dwSplit + hp.split_index);
			}
			if (dwType & DATA_INDIRECT) dwDataIn = *(DWORD *)(dwDataIn + hp.index);
			dwCount = GetLength(dwDataBase, dwDataIn);
		}

		if (dwCount == 0 || dwCount > PIPE_BUFFER_SIZE - sizeof(ThreadParam)) return;

		if (hp.length_offset == 1) {
			dwDataIn &= 0xffff;
			if ((dwType & BIG_ENDIAN) && (dwDataIn >> 8)) dwDataIn = _byteswap_ushort(dwDataIn & 0xffff);
			if (dwCount == 1) dwDataIn &= 0xff;
			*(WORD*)pbData = dwDataIn & 0xffff;
		}
		else ::memcpy(pbData, (void*)dwDataIn, dwCount);

		if (hp.filter_fun && !hp.filter_fun(pbData, &dwCount, &hp, 0) || dwCount <= 0) return;

		if (dwType & (NO_CONTEXT | FIXING_SPLIT)) dwRetn = 0;

		TextOutput({ GetCurrentProcessId(), dwAddr, dwRetn, dwSplit }, pbData, dwCount);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) 
	{
		ConsoleOutput("Textractor: Send ERROR (likely an incorrect H-code)");
	}
}

bool TextHook::InsertHookCode()
{
	// jichi 9/17/2013: might raise 0xC0000005 AccessViolationException on win7
	// Artikash 10/30/2018: No, I think that's impossible now that I moved to minhook
	if (hp.type & MODULE_OFFSET)  // Map hook offset to real address
		if (hp.type & FUNCTION_OFFSET)
			if (FARPROC function = GetProcAddress(GetModuleHandleW(hp.module), hp.function)) hp.insertion_address += (uint64_t)function;
			else return ConsoleOutput(FUNC_MISSING), false;
		else if (HMODULE moduleBase = GetModuleHandleW(hp.module)) hp.insertion_address += (uint64_t)moduleBase;
		else return ConsoleOutput(MODULE_MISSING), false;

	void* original;
insert:
	if (MH_STATUS err = MH_CreateHook((void*)hp.insertion_address, (void*)trampoline, &original))
		if (err == MH_ERROR_ALREADY_CREATED)
		{
			RemoveHook(hp.insertion_address);
			goto insert; // FIXME: i'm too lazy to do this properly right now...
		}
		else
		{
			ConsoleOutput(MH_StatusToString(err));
			return false;
		}

#ifndef _WIN64
	*(TextHook**)(common_hook + 9) = this;
	*(void(TextHook::**)(DWORD))(common_hook + 14) = &TextHook::Send;
	*(void**)(common_hook + 24) = original;
	memcpy(trampoline, common_hook, sizeof(common_hook));
#else // _WIN32
	BYTE* original;
	MH_CreateHook((void*)hp.address, (void*)trampoline, (void**)&original);
	memcpy(trampoline, common_hook, sizeof(common_hook));
	void* thisPtr = (void*)this;
	memcpy(trampoline + 30, &thisPtr, sizeof(void*));
	auto sendPtr = (void(TextHook::*)(void*))&TextHook::Send;
	memcpy(trampoline + 46, &sendPtr, sizeof(sendPtr));
	memcpy(trampoline + sizeof(common_hook) - 8, &original, sizeof(void*));
#endif // _WIN64

	return MH_EnableHook((void*)hp.insertion_address) == MH_OK;
}
#endif // _WIN32

DWORD WINAPI TextHook::Reader(LPVOID hookPtr)
{
	TextHook* hook = (TextHook*)hookPtr;
	BYTE buffer[PIPE_BUFFER_SIZE] = {};
	unsigned int changeCount = 0;
	int dataLen = 0;
	__try
	{
		const void* currentAddress = (void*)hook->hp.insertion_address;
		while (WaitForSingleObject(hook->readerEvent, 500) == WAIT_TIMEOUT)
		{
			if (hook->hp.type & DATA_INDIRECT) currentAddress = *((char**)hook->hp.insertion_address + hook->hp.index);
			if (memcmp(buffer, currentAddress, dataLen + 1) == 0)
			{
				changeCount = 0;
				continue;
			}
			if (++changeCount > 10)
			{
				ConsoleOutput(GARBAGE_MEMORY);
				hook->Clear();
				break;
			}

			if (hook->hp.type & USING_UNICODE)
				dataLen = wcslen((const wchar_t*)currentAddress) * 2;
			else
				dataLen = strlen((const char*)currentAddress);

			memcpy(buffer, currentAddress, dataLen + 1);
			TextOutput({ GetCurrentProcessId(), hook->hp.insertion_address, 0, 0 }, buffer, dataLen);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ConsoleOutput("Textractor: Reader ERROR (likely an incorrect R-code)");
		hook->Clear();
	}
	return 0;
}

bool TextHook::InsertReadCode()
{
	readerThread = CreateThread(nullptr, 0, Reader, this, 0, nullptr);
	readerEvent = CreateEventW(nullptr, FALSE, FALSE, NULL);
	return true;
}

void TextHook::RemoveHookCode()
{
	MH_DisableHook((void*)hp.insertion_address);
	MH_RemoveHook((void*)hp.insertion_address);
}

void TextHook::RemoveReadCode()
{
	SetEvent(readerEvent);
	if (GetThreadId(readerThread) != GetCurrentThreadId()) WaitForSingleObject(readerThread, 1000);
	CloseHandle(readerEvent);
	CloseHandle(readerThread);
}

void TextHook::Clear()
{
	LOCK(*viewMutex);
	ConsoleOutput(REMOVING_HOOK, hp.name);
	if (hp.type & DIRECT_READ) RemoveReadCode();
	else RemoveHookCode();
	NotifyHookRemove(hp.insertion_address);
	memset(this, 0, sizeof(TextHook)); // jichi 11/30/2013: This is the original code of ITH
}

int TextHook::GetLength(DWORD base, DWORD in)
{
	if (base == 0)
		return 0;
	int len;
	switch (hp.length_offset) {
	default: // jichi 12/26/2013: I should not put this default branch to the end
		len = *((int *)base + hp.length_offset);
		if (len >= 0) {
			if (hp.type & USING_UNICODE)
				len <<= 1;
			break;
		}
		else if (len != -1)
			break;
		//len == -1 then continue to case 0.
	case 0:
		if (hp.type & USING_UNICODE)
			len = wcslen((const wchar_t *)in) << 1;
		else
			len = strlen((const char *)in);
		break;
	case 1:
		if (hp.type & USING_UNICODE)
			len = 2;
		else {
			if (hp.type & BIG_ENDIAN)
				in >>= 8;
			len = LeadByteTable[in & 0xff];  //Slightly faster than IsDBCSLeadByte
		}
		break;
	}
	// jichi 12/25/2013: This function originally return -1 if failed
	//return len;
	return max(0, len);
}

// EOF

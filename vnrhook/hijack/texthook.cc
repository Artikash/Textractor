// texthook.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/texthook.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
# pragma warning (disable:4018)   // C4018: sign/unsigned mismatch
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "hijack/texthook.h"
#include "MinHook.h"
#include "engine/match.h"
#include "except.h"
#include "main.h"
#include "pipe.h"
#include "const.h"
#include "ithsys/ithsys.h"
#include "disasm/disasm.h"
#include "growl.h"
#include <Psapi.h>

TextHook *hookman;

// - Unnamed helpers -

namespace { // unnamed
#ifndef _WIN64

	const BYTE common_hook[] = {
	  0x9c, // pushfd
	  0x60, // pushad
	  0x9c, // pushfd
	  0x8d,0x54,0x24,0x28, // lea edx,[esp+0x28] ; esp value
	  0x8b,0x32,     // mov esi,[edx] ; return address
	  0xb9, 0,0,0,0, // mov ecx, $ ; pointer to TextHook
	  0xe8, 0,0,0,0, // call @hook
	  0x9d, // popfd
	  0x61, // popad
	  0x9d,  // popfd
	  0xe9  // jmp @original
	};

	DWORD Hash(std::wstring module)
	{
		DWORD hash = 0;
		for (auto i : module) hash = _rotr(hash, 7) + i;
		return hash;
	}

	//copy original instruction
	//jmp back
	DWORD GetModuleBase(DWORD hash)
	{
		HMODULE allModules[1000];
		DWORD size;
		EnumProcessModules(GetCurrentProcess(), allModules, sizeof(allModules), &size);
		wchar_t name[MAX_PATH];
		for (int i = 0; i < size / sizeof(HMODULE); ++i)
		{
			GetModuleFileNameW(allModules[i], name, MAX_PATH);
			_wcslwr(name);
			if (Hash(wcsrchr(name, L'\\') + 1) == hash) return (DWORD)allModules[i];
		}
		return 0;
	}

	__declspec(naked) // jichi 10/2/2013: No prolog and epilog
		int ProcessHook(DWORD dwDataBase, DWORD dwRetn, TextHook *hook) // Use SEH to ensure normal execution even bad hook inserted.
	{
		// jichi 12/17/2013: The function parameters here are meaning leass. The parameters are in esi and edi
		__asm
		{
			push esi
			push edx
			call TextHook::Send
			retn    // jichi 12/13/2013: return near, see: http://stackoverflow.com/questions/1396909/ret-retn-retf-how-to-use-them
		}
	}
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
} // unnamed namespace

// - TextHook methods -

bool TextHook::InsertHook()
{
	bool ret = false;
	//ConsoleOutput("vnrcli:InsertHook: enter");
	WaitForSingleObject(hmMutex, 0);
	if (hp.type & DIRECT_READ) ret = InsertReadCode();
#ifndef _WIN64
	else ret = InsertHookCode();
#endif
	ReleaseMutex(hmMutex);
	//ConsoleOutput("vnrcli:InsertHook: leave");
	return ret;
}

#ifndef _WIN64
// jichi 12/2/2013: This function mostly return 0.
// It return the hook address only for auxiliary case.
// However, because no known hooks are auxiliary, this function always return 0.
//
// jichi 5/11/2014:
// - dwDataBase: the stack address
// - dwRetn: the return address of the hook
DWORD TextHook::Send(DWORD dwDataBase, DWORD dwRetn)
{
	DWORD ret = 0;
	ITH_WITH_SEH(ret = UnsafeSend(dwDataBase, dwRetn));
	return ret;
}

DWORD TextHook::UnsafeSend(DWORD dwDataBase, DWORD dwRetn)
{
	DWORD dwCount,
		dwAddr,
		dwDataIn,
		dwSplit;
	BYTE pbData[PIPE_BUFFER_SIZE];
	DWORD dwType = hp.type;

	dwAddr = hp.address;

	/** jichi 12/24/2014
	 *  @param  addr  function address
	 *  @param  frame  real address of the function, supposed to be the same as addr
	 *  @param  stack  address of current stack - 4
	 *  @return  If success, which is reverted
	 */
	if (::trigger)
		::trigger = Engine::InsertDynamicHook((LPVOID)dwAddr, *(DWORD *)(dwDataBase - 0x1c), *(DWORD *)(dwDataBase - 0x18));

	// jichi 10/24/2014: generic hook function
	if (hp.hook_fun && !hp.hook_fun(dwDataBase, &hp))
		hp.hook_fun = nullptr;

	if (dwType & HOOK_EMPTY) // jichi 10/24/2014: dummy hook only for dynamic hook
		return 0;

	dwCount = 0;
	dwSplit = 0;
	dwDataIn = *(DWORD *)(dwDataBase + hp.offset); // default value

	if (hp.text_fun) {
		hp.text_fun(dwDataBase, &hp, 0, &dwDataIn, &dwSplit, &dwCount);
	}
	else {
		if (dwDataIn == 0)
			return 0;
		if (dwType & FIXING_SPLIT)
			dwSplit = FIXED_SPLIT_VALUE; // fuse all threads, and prevent floating
		else if (dwType & USING_SPLIT) {
			dwSplit = *(DWORD *)(dwDataBase + hp.split);
			if (dwType & SPLIT_INDIRECT) {
				if (IthGetMemoryRange((LPVOID)(dwSplit + hp.split_index), 0, 0))
					dwSplit = *(DWORD *)(dwSplit + hp.split_index);
				else
					return 0;
			}
		}
		if (dwType & DATA_INDIRECT) {
			if (IthGetMemoryRange((LPVOID)(dwDataIn + hp.index), 0, 0))
				dwDataIn = *(DWORD *)(dwDataIn + hp.index);
			else
				return 0;
		}
		dwCount = GetLength(dwDataBase, dwDataIn);
	}
	// jichi 12/25/2013: validate data size
	if (dwCount == 0 || dwCount > PIPE_BUFFER_SIZE - sizeof(ThreadParam))
		return 0;

	if (hp.length_offset == 1) {
		dwDataIn &= 0xffff;
		if ((dwType & BIG_ENDIAN) && (dwDataIn >> 8))
			dwDataIn = _byteswap_ushort(dwDataIn & 0xffff);
		if (dwCount == 1)
			dwDataIn &= 0xff;
		*(WORD *)(pbData + sizeof(ThreadParam)) = dwDataIn & 0xffff;
	}
	else
		::memcpy(pbData + sizeof(ThreadParam), (void *)dwDataIn, dwCount);

	// jichi 10/14/2014: Add filter function
	if (hp.filter_fun && !hp.filter_fun(pbData + sizeof(ThreadParam), &dwCount, &hp, 0) || dwCount <= 0) {
		return 0;
	}

	if (dwType & (NO_CONTEXT | FIXING_SPLIT))
		dwRetn = 0;

	*(ThreadParam*)pbData = { GetCurrentProcessId(), dwAddr, dwRetn, dwSplit };
	if (dwCount) {
		DWORD unused;

		//CliLockPipe();
		WriteFile(::hookPipe, pbData, dwCount + sizeof(ThreadParam), &unused, nullptr);
		//CliUnlockPipe();
	}
	return 0;

}

bool TextHook::InsertHookCode()
{
	bool ret = false;
	// jichi 9/17/2013: might raise 0xC0000005 AccessViolationException on win7
	__try { ret = UnsafeInsertHookCode(); }
	__except (1) {};
	return ret;
}


bool TextHook::UnsafeInsertHookCode()
{
	if (hp.module && (hp.type & MODULE_OFFSET))  // Map hook offset to real address.
	{
		if (DWORD base = GetModuleBase(hp.module)) hp.address += base;
		else return ConsoleOutput("NextHooker: UnsafeInsertHookCode: FAILED: module not present"), false;
		hp.type &= ~MODULE_OFFSET;
	}

	BYTE* original;
	insert:
	if (MH_STATUS err = MH_CreateHook((void*)hp.address, (void*)trampoline, (void**)&original))
		if (err == MH_ERROR_ALREADY_CREATED)
		{
			RemoveHook(hp.address);
			goto insert; // FIXME: i'm too lazy to do this properly right now...
		}
		else
		{
			ConsoleOutput(("NextHooker: UnsafeInsertHookCode: FAILED: error " + std::string(MH_StatusToString(err))).c_str());
			return false;
		}

	void* thisPtr = (void*)this;
	void* funcPtr = (void*)((BYTE*)ProcessHook - (BYTE*)(trampoline + 19));
	DWORD dist = original - (trampoline + sizeof(common_hook)) - 4;

	memcpy(trampoline, common_hook, sizeof(common_hook));
	memcpy(trampoline + 10, &thisPtr, sizeof(void*));
	memcpy(trampoline + 15, &funcPtr, sizeof(void*));
	memcpy(trampoline + sizeof(common_hook), &dist, sizeof(dist));

	//BYTE* original;
	//MH_CreateHook((void*)hp.address, (void*)trampoline, (void**)&original);
	//memcpy(trampoline, common_hook, sizeof(common_hook));
	//void* thisPtr = (void*)this;
	//memcpy(trampoline + 30, &thisPtr, sizeof(void*));
	//auto sendPtr = (void(TextHook::*)(void*))&TextHook::Send;
	//memcpy(trampoline + 46, &sendPtr, sizeof(sendPtr));
	//memcpy(trampoline + sizeof(common_hook) - 8, &original, sizeof(void*));

	if (MH_EnableHook((void*)hp.address) != MH_OK) return false;

	return true;
}
#endif // _WIN32

DWORD WINAPI ReaderThread(LPVOID hookPtr)
{
	TextHook* hook = (TextHook*)hookPtr;
	BYTE buffer[PIPE_BUFFER_SIZE] = {};
	unsigned int changeCount = 0;
	int dataLen = 0;
	const void* currentAddress = (void*)hook->hp.address;
	while (true)
	{
		if (!IthGetMemoryRange((void*)hook->hp.address, nullptr, nullptr))
		{
			ConsoleOutput("NextHooker: can't read desired address");
			break;
		}
		if (hook->hp.type & DATA_INDIRECT) currentAddress = *((char**)hook->hp.address + hook->hp.index);
		if (!IthGetMemoryRange(currentAddress, nullptr, nullptr))
		{
			ConsoleOutput("NextHooker: can't read desired address");
			break;
		}
		Sleep(500);
		if (memcmp(buffer + sizeof(ThreadParam), currentAddress, dataLen + 1) == 0)
		{
			changeCount = 0;
			continue;
		}
		if (++changeCount > 10)
		{
			ConsoleOutput("NextHooker: memory constantly changing, useless to read");
			break;
		}

		if (hook->hp.type & USING_UNICODE)
			dataLen = wcslen((const wchar_t*)currentAddress) * 2;
		else
			dataLen = strlen((const char*)currentAddress);

		*(ThreadParam*)buffer = { GetCurrentProcessId(), hook->hp.address, 0, 0 };
		memcpy(buffer + sizeof(ThreadParam), currentAddress, dataLen + 1);
		DWORD unused;
		WriteFile(::hookPipe, buffer, dataLen + sizeof(ThreadParam), &unused, nullptr);
	}
	ConsoleOutput("NextHooker: remove read code");
	hook->ClearHook();
	return 0;
}

bool TextHook::InsertReadCode()
{
	//RemoveHook(hp.address); // Artikash 8/25/2018: clear existing
	hp.readerHandle = CreateThread(nullptr, 0, ReaderThread, this, 0, nullptr);
	return true;
}

void TextHook::InitHook(const HookParam &h, LPCSTR name, WORD set_flag)
{
	WaitForSingleObject(hmMutex, 0);
	hp = h;
	hp.type |= set_flag;
	if (name && name != hook_name) SetHookName(name);
	ReleaseMutex(hmMutex);
}

void TextHook::RemoveHookCode()
{
	MH_DisableHook((void*)hp.address);
	MH_RemoveHook((void*)hp.address);
}

void TextHook::RemoveReadCode()
{
	TerminateThread(hp.readerHandle, 0);
	CloseHandle(hp.readerHandle);
}

void TextHook::ClearHook()
{
	WaitForSingleObject(hmMutex, 0);
	if (hook_name) ConsoleOutput(("NextHooker: removing hook: " + std::string(hook_name)).c_str());
	if (hp.type & DIRECT_READ) RemoveReadCode();
	else RemoveHookCode();
	NotifyHookRemove(hp.address);
	if (hook_name) delete[] hook_name;
	memset(this, 0, sizeof(TextHook)); // jichi 11/30/2013: This is the original code of ITH
	ConsoleOutput("NextHooker:RemoveHook: leave");
	ReleaseMutex(hmMutex);
}

void TextHook::SetHookName(LPCSTR name)
{
	name_length = strlen(name) + 1;
	if (hook_name) delete[] hook_name;
	hook_name = new char[name_length];
	strcpy(hook_name, name);
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

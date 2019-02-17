// texthook.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/texthook.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#include "texthook.h"
#include "engine/match.h"
#include "main.h"
#include "const.h"
#include "defs.h"
#include "text.h"
#include "ithsys/ithsys.h"

extern WinMutex viewMutex;

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
	int this_offset = 9, send_offset = 14, original_offset = 24;
#else
	BYTE common_hook[] = {
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
		0x48, 0x8d, 0x94, 0x24, 0xa8, 0x00, 0x00, 0x00, // lea rdx,[rsp+0xa8]
		0x48, 0xb9, 0,0,0,0,0,0,0,0, // mov rcx,@this
		0x48, 0xb8, 0,0,0,0,0,0,0,0, // mov rax,@TextHook::Send
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
	int this_offset = 50, send_offset = 60, original_offset = 116;
#endif

	bool trigger = false;

	enum { TEXT_BUFFER_SIZE = PIPE_BUFFER_SIZE - sizeof(ThreadParam) };
} // unnamed namespace

void SetTrigger()
{
	trigger = true;
}

// - TextHook methods -

bool TextHook::Insert(HookParam h, DWORD set_flag)
{
	std::scoped_lock lock(viewMutex);
	hp = h;
	address = hp.address;
	hp.type |= set_flag;
	if (hp.type & USING_UTF8) hp.codepage = CP_UTF8;
	if (hp.type & DIRECT_READ) return InsertReadCode();
	else return InsertHookCode();
}

// jichi 5/11/2014:
// - dwDataBase: the stack address
void TextHook::Send(uintptr_t dwDataBase)
{
	__try
	{
#ifndef _WIN64
		DWORD dwCount = 0,
			dwSplit = 0,
			dwDataIn = *(DWORD*)(dwDataBase + hp.offset), // default values
			dwRetn = *(DWORD*)dwDataBase; // first value on stack (if hooked start of function, this is return address)

		if (trigger) trigger = Engine::InsertDynamicHook(location, *(DWORD *)(dwDataBase - 0x1c), *(DWORD *)(dwDataBase - 0x18));

		// jichi 10/24/2014: generic hook function
		if (hp.hook_fun && !hp.hook_fun(dwDataBase, &hp)) hp.hook_fun = nullptr;

		if (hp.type & HOOK_EMPTY) return; // jichi 10/24/2014: dummy hook only for dynamic hook

		if (hp.text_fun) {
			hp.text_fun(dwDataBase, &hp, 0, &dwDataIn, &dwSplit, &dwCount);
		}
		else {
			if (hp.type & FIXING_SPLIT) dwSplit = FIXED_SPLIT_VALUE; // fuse all threads, and prevent floating
			else if (hp.type & USING_SPLIT) {
				dwSplit = *(DWORD *)(dwDataBase + hp.split);
				if (hp.type & SPLIT_INDIRECT) dwSplit = *(DWORD *)(dwSplit + hp.split_index);
			}
			if (hp.type & DATA_INDIRECT) dwDataIn = *(DWORD *)(dwDataIn + hp.index);
			dwCount = GetLength(dwDataBase, dwDataIn);
		}

		if (dwCount == 0) return;
		if (dwCount > TEXT_BUFFER_SIZE) dwCount = TEXT_BUFFER_SIZE;
		BYTE pbData[TEXT_BUFFER_SIZE];
		if (hp.length_offset == 1) {
			dwDataIn &= 0xffff;
			if ((hp.type & BIG_ENDIAN) && (dwDataIn >> 8)) dwDataIn = _byteswap_ushort(dwDataIn & 0xffff);
			if (dwCount == 1) dwDataIn &= 0xff;
			*(WORD*)pbData = dwDataIn & 0xffff;
		}
		else ::memcpy(pbData, (void*)dwDataIn, dwCount);

		if (hp.filter_fun && !hp.filter_fun(pbData, &dwCount, &hp, 0) || dwCount <= 0) return;

		if (hp.type & (NO_CONTEXT | FIXING_SPLIT)) dwRetn = 0;

		TextOutput({ GetCurrentProcessId(), address, dwRetn, dwSplit }, pbData, dwCount);
#else // _WIN32
		int count = 0;
		ThreadParam tp = { GetCurrentProcessId(), address, *(uintptr_t*)dwDataBase, 0 }; // first value on stack (if hooked start of function, this is return address)
		uintptr_t data = *(uintptr_t*)(dwDataBase + hp.offset); // default value

		if (hp.type & USING_SPLIT)
		{
			tp.ctx2 = *(uintptr_t*)(dwDataBase + hp.split);
			if (hp.type & SPLIT_INDIRECT) tp.ctx2 = *(uintptr_t*)(tp.ctx2 + hp.split_index);
		}
		if (hp.type & DATA_INDIRECT) data = *(uintptr_t*)(data + hp.index);

		count = GetLength(dwDataBase, data);
		if (count == 0) return;
		if (count > TEXT_BUFFER_SIZE) count = TEXT_BUFFER_SIZE;
		BYTE pbData[TEXT_BUFFER_SIZE];
		if (hp.length_offset == 1)
		{
			data &= 0xffff;
			if ((hp.type & BIG_ENDIAN) && (data >> 8)) data = _byteswap_ushort(data & 0xffff);
			if (count == 1) data &= 0xff;
			*(WORD*)pbData = data & 0xffff;
		}
		else ::memcpy(pbData, (void*)data, count);

		if (hp.type & (NO_CONTEXT | FIXING_SPLIT)) tp.ctx = 0;

		TextOutput(tp, pbData, count);
#endif // _WIN64
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (!err)
		{
			ConsoleOutput(SEND_ERROR);
			err = true;
		}
	}
}

bool TextHook::InsertHookCode()
{
	// jichi 9/17/2013: might raise 0xC0000005 AccessViolationException on win7
	// Artikash 10/30/2018: No, I think that's impossible now that I moved to minhook
	if (hp.type & MODULE_OFFSET)  // Map hook offset to real address
		if (hp.type & FUNCTION_OFFSET)
			if (FARPROC function = GetProcAddress(GetModuleHandleW(hp.module), hp.function)) address += (uint64_t)function;
			else return ConsoleOutput(FUNC_MISSING), false;
		else if (HMODULE moduleBase = GetModuleHandleW(hp.module)) address += (uint64_t)moduleBase;
		else return ConsoleOutput(MODULE_MISSING), false;

	void* original;
	MH_STATUS error;
	while ((error = MH_CreateHook(location, trampoline, &original)) != MH_OK)
		if (error == MH_ERROR_ALREADY_CREATED) RemoveHook(address);
		else return ConsoleOutput(MH_StatusToString(error)), false;

	*(TextHook**)(common_hook + this_offset) = this;
	*(void(TextHook::**)(uintptr_t))(common_hook + send_offset) = &TextHook::Send;
	*(void**)(common_hook + original_offset) = original;
	memcpy(trampoline, common_hook, sizeof(common_hook));
	return MH_EnableHook(location) == MH_OK;
}

DWORD WINAPI TextHook::Reader(LPVOID hookPtr)
{
	TextHook* This = (TextHook*)hookPtr;
	BYTE buffer[TEXT_BUFFER_SIZE] = {};
	int changeCount = 0, dataLen = 0;
	__try
	{
		uint64_t currentAddress = This->address;
		while (WaitForSingleObject(This->readerEvent, 500) == WAIT_TIMEOUT)
		{
			if (This->hp.type & DATA_INDIRECT) currentAddress = *(uintptr_t*)This->address + This->hp.index;
			if (memcmp(buffer, (void*)currentAddress, dataLen + 2) == 0)
			{
				changeCount = 0;
				continue;
			}
			if (++changeCount > 10)
			{
				ConsoleOutput(GARBAGE_MEMORY);
				This->Clear();
				break;
			}

			if (This->hp.type & USING_UNICODE) dataLen = wcslen((wchar_t*)currentAddress) * 2;
			else dataLen = strlen((char*)currentAddress);
			if (dataLen > TEXT_BUFFER_SIZE - 2) dataLen = TEXT_BUFFER_SIZE - 2;
			memcpy(buffer, (void*)currentAddress, dataLen + 2);
			TextOutput({ GetCurrentProcessId(), This->address, 0, 0 }, buffer, dataLen);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ConsoleOutput(READ_ERROR);
		This->Clear();
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
	MH_DisableHook(location);
	MH_RemoveHook(location);
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
	std::scoped_lock lock(viewMutex);
	if (*hp.name) ConsoleOutput(REMOVING_HOOK, hp.name);
	if (hp.type & DIRECT_READ) RemoveReadCode();
	else RemoveHookCode();
	NotifyHookRemove(address);
	memset(this, 0, sizeof(TextHook)); // jichi 11/30/2013: This is the original code of ITH
}

int TextHook::GetLength(uintptr_t base, uintptr_t in)
{
	int len;
	switch (hp.length_offset) {
	default: // jichi 12/26/2013: I should not put this default branch to the end
		len = *((uintptr_t*)base + hp.length_offset);
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

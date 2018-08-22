// texthook.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/texthook.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
# pragma warning (disable:4018)   // C4018: sign/unsigned mismatch
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "src/hijack/texthook.h"
#include "src/engine/match.h"
#include "src/except.h"
#include "src/main.h"
#include "include/const.h"
#include "ithsys/ithsys.h"
#include "disasm/disasm.h"
//#include "winseh/winseh.h"

//#define ConsoleOutput(...)   (void)0    // jichi 9/17/2013: I don't need this ><

// - Global variables -

// 10/14/2014 jichi: disable GDI hooks
static bool gdi_hook_enabled_ = true; // enable GDI by default
static bool gdiplus_hook_enabled_ = false; // disable GDIPlus by default
bool GDIHooksEnabled() { return ::gdi_hook_enabled_; }
bool GDIPlusHooksEnabled() { return ::gdiplus_hook_enabled_; }
void EnableGDIHooks() { ::gdi_hook_enabled_ = true; }
void EnableGDIPlusHooks() { ::gdiplus_hook_enabled_ = true; }
void DisableGDIHooks() { ::gdi_hook_enabled_ = false; }
void DisableGDIPlusHooks() { ::gdiplus_hook_enabled_ = false; }

//FilterRange filter[8];

DWORD flag,
      enter_count;

TextHook *hookman,
         *current_available;

// - Unnamed helpers -

#ifndef _WIN64
namespace { // unnamed
//provide const time hook entry.
int userhook_count;

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
  0x9d  // popfd
};

/**
 *  jichi 7/19/2014
 *
 *  @param  original_addr
 *  @param  new_addr
 *  @param  hook_len
 *  @param  original_len
 *  @return  -1 if failed, else 0 if ?, else ?
 */
int MapInstruction(DWORD original_addr, DWORD new_addr, BYTE &hook_len, BYTE &original_len)
{
  int flag = 0;
  DWORD l = 0;
  const BYTE *r = (const BYTE *)original_addr;  // 7/19/2014 jichi: original address is not modified
  BYTE *c = (BYTE *)new_addr;                   // 7/19/2014 jichi: but new address might be modified
  while((r - (BYTE *) original_addr) < 5) {
    l = ::disasm(r);
    if (l == 0) {
      ConsoleOutput("vnrcli:MapInstruction: FAILED: failed to disasm");
      return -1;
    }

    ::memcpy(c, r, l);
    if (*r >= 0x70 && *r < 0x80) {
      c[0] = 0xf;
      c[1] = *r + 0x10;
      c += 6;
      __asm
      {
        mov eax,r
        add eax,2
        movsx edx,byte ptr [eax-1]
        add edx,eax
        mov eax,c
        sub edx,eax
        mov [eax-4],edx
      }
    } else if (*r == 0xeb) {
      c[0] = 0xe9;
      c += 5;
      __asm
      {
        mov eax,r
        add eax,2
        movsx edx,[eax-1]
        add edx,eax
        mov eax,c
        sub edx,eax
        mov [eax-4],edx
      }
      if (r - (BYTE *)original_addr < 5 - l) {
        ConsoleOutput("vnrcli:MapInstruction: not safe to move instruction right after short jmp");
        return -1; // Not safe to move instruction right after short jmp.
      } else
        flag = 1;
    } else if (*r == 0xe8 || *r == 0xe9) {
      c[0]=*r;
      c += 5;
      flag = (*r == 0xe9);
      __asm
      {
        mov eax,r
        add eax,5
        mov edx,[eax-4]
        add edx,eax
        mov eax,c
        sub edx,eax
        mov [eax-4],edx
      }
    } else if (*r == 0xf && (*(r + 1) >> 4) == 0x8) {
      c += 6;
      __asm
      {
        mov eax,r
        mov edx,dword ptr [eax+2]
        add eax,6
        add eax,edx
        mov edx,c
        sub eax,edx
        mov [edx-4],eax
      }
    }
    else
      c += l;
    r += l;
  }
  original_len = r - (BYTE *)original_addr;
  hook_len = c - (BYTE *)new_addr;
  return flag;
}

//copy original instruction
//jmp back
DWORD GetModuleBase(DWORD hash)
{
  __asm
  {
    mov eax,fs:[0x30]
    mov eax,[eax+0xc]
    mov esi,[eax+0x14]
    mov edi,_wcslwr
listfind:
    mov edx,[esi+0x28]
    test edx,edx
    jz notfound
    push edx
    call edi
    pop edx
    xor eax,eax
calc:
    movzx ecx, word ptr [edx]
    test cl,cl
    jz fin
    ror eax,7
    add eax,ecx
    add edx,2
    jmp calc
fin:
    cmp eax,[hash]
    je found
    mov esi,[esi]
    jmp listfind
notfound:
    xor eax,eax
    jmp termin
found:
    mov eax,[esi+0x10]
termin:
  }
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

} // unnamed namespace
#endif // _WIN32

// - TextHook methods -

int TextHook::InsertHook()
{
  int ok = 1;
  //ConsoleOutput("vnrcli:InsertHook: enter");
  WaitForSingleObject(hmMutex, 0);
  if (hp.type & DIRECT_READ) ok = InsertReadCode();
#ifndef _WIN64
  else ok = InsertHookCode();
#endif
  ReleaseMutex(hmMutex);
  //ConsoleOutput("vnrcli:InsertHook: leave");
  return ok;
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
    ::trigger = Engine::InsertDynamicHook((LPVOID)dwAddr, *(DWORD *)(dwDataBase - 0x1c), *(DWORD *)(dwDataBase-0x18));

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
    } else {
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
    if (dwCount == 0 || dwCount > PIPE_BUFFER_SIZE - HEADER_SIZE)
      return 0;

    if (hp.length_offset == 1) {
      dwDataIn &= 0xffff;
      if ((dwType & BIG_ENDIAN) && (dwDataIn >> 8))
        dwDataIn = _byteswap_ushort(dwDataIn & 0xffff);
      if (dwCount == 1)
        dwDataIn &= 0xff;
      *(WORD *)(pbData + HEADER_SIZE) = dwDataIn & 0xffff;
    }
    else
      ::memcpy(pbData + HEADER_SIZE, (void *)dwDataIn, dwCount);

    // jichi 10/14/2014: Add filter function
    if (hp.filter_fun && !hp.filter_fun(pbData + HEADER_SIZE, &dwCount, &hp, 0) || dwCount <= 0) {
      return 0;
    }

    *(DWORD *)pbData = dwAddr;
    if (dwType & (NO_CONTEXT|FIXING_SPLIT))
      dwRetn = 0;

    *((DWORD *)pbData + 1) = dwRetn;
    *((DWORD *)pbData + 2) = dwSplit;
    if (dwCount) {
		DWORD unused;

      //CliLockPipe();
	  WriteFile(::hookPipe, pbData, dwCount + HEADER_SIZE, &unused, nullptr);
      //CliUnlockPipe();
    }
  return 0;

}

int TextHook::InsertHookCode()
{
  DWORD ret = no;
  // jichi 9/17/2013: might raise 0xC0000005 AccessViolationException on win7
  ITH_WITH_SEH(ret = UnsafeInsertHookCode());
  //if (ret == no)
  //  ITH_WARN(L"Failed to insert hook");
  return ret;
}


int TextHook::UnsafeInsertHookCode()
{
  //ConsoleOutput("vnrcli:UnsafeInsertHookCode: enter");
  if (hp.module && (hp.type & MODULE_OFFSET)) { // Map hook offset to real address.
	  if (DWORD base = GetModuleBase(hp.module)) {
		  hp.address += base;
	  }
	  else {
		  currentHook--;
		  ConsoleOutput("vnrcli:UnsafeInsertHookCode: FAILED: module not present");
		  return no;
	  }
	  hp.type &= ~MODULE_OFFSET;
  }


  {
    TextHook *it = hookman;
    for (int i = 0; (i < currentHook) && it; it++) { // Check if there is a collision.
      if (it->Address())
        i++;
      //it = hookman + i;
      if (it == this)
        continue;
      if (it->Address() <= hp.address &&
          it->Address() + it->Length() > hp.address) {
        it->ClearHook();
        break;
      }
    }
  }

  // Verify hp.address.
  if (!IthGetMemoryRange((LPCVOID)hp.address, nullptr, nullptr))
  {
	  ConsoleOutput("NextHooker: FAILED: cannot access requested memory");
	  return no;
  }

  memcpy(recover, common_hook, sizeof(common_hook));
  void* thisPtr = (void*)this;
  void* funcPtr = (void*)((BYTE*)ProcessHook - (BYTE*)(recover + 19));
  memcpy(recover + 10, &thisPtr, sizeof(void*));
  memcpy(recover + 15, &funcPtr, sizeof(void*));
  BYTE *c = (BYTE *)hp.address,
       *r = recover;
  BYTE inst[] = // jichi 9/27/2013: Why 8? Only 5 bytes will be written using NtWriteVirtualMemory
  { 
	  0xe9, 0, 0, 0, 0, // jmp recover 
	  0xcc, 0xcc, 0xcc // int3
  };
  void* relRecover = (void*)(recover - (BYTE*)hp.address - 5);
  memcpy(inst + 1, &relRecover, sizeof(void*));
  r += sizeof(common_hook);
  hp.hook_len = 5;
  int address = hp.address;
  switch (MapInstruction(hp.address, (DWORD)r, hp.hook_len, hp.recover_len)) {
  case -1:
    ConsoleOutput("vnrcli:UnsafeInsertHookCode: FAILED: failed to map instruction");
    return no;
  case 0:
    __asm
    {
      mov ecx,this
      movzx eax,[ecx]hp.hook_len
      movzx edx,[ecx]hp.recover_len
      add edx,address
      add eax,r
      add eax,5
      sub edx,eax
      mov [eax-5],0xe9 // jichi 9/27/2013: 0xe9 is jump
      mov [eax-4],edx
    }
  }
  // jichi 9/27/2013: Save the original instructions in the memory
  memcpy(original, (LPVOID)hp.address, hp.recover_len);
  //Check if the new hook range conflict with existing ones. Clear older if conflict.
  {
    TextHook *it = hookman;
    for (int i = 0; i < currentHook; it++) {
      if (it->Address())
        i++;
      if (it == this)
        continue;
      if (it->Address() >= hp.address &&
          it->Address() < hp.hook_len + hp.address) {
        it->ClearHook();
        break;
      }
    }
  }
  
  DWORD old;
  LPVOID addr = (void*)hp.address;
  VirtualProtect(addr, sizeof(inst), PAGE_EXECUTE_READWRITE, &old);
  memcpy(addr, inst, hp.recover_len);
  FlushInstructionCache(GetCurrentProcess(), addr, hp.recover_len);

  return 0;
}
#endif // _WIN32

DWORD WINAPI ReaderThread(LPVOID threadParam)
{
	TextHook* hook = (TextHook*)threadParam;
	BYTE buffer[PIPE_BUFFER_SIZE] = {};
	unsigned int changeCount = 0;
	int dataLen = 0;
	const char* currentAddress = (char*)hook->hp.address;
	while (true)
	{
		Sleep(500);
		if (memcmp(buffer + HEADER_SIZE, currentAddress, dataLen) == 0)
		{
			changeCount = 0;
			continue;
		}
		if (++changeCount > 10)
		{
			ConsoleOutput("NextHooker: memory constantly changing, useless to read");
			ConsoleOutput("NextHooker: remove read code");
			break;
		}

		if (hook->hp.type & USING_UNICODE)
			dataLen = wcslen((const wchar_t*)currentAddress) * 2;
		else
			dataLen = strlen(currentAddress);

		*(DWORD*)buffer = hook->hp.address;
		*(DWORD*)(buffer + 4) = 0;
		*(DWORD*)(buffer + 8) = 0;
		memcpy(buffer + HEADER_SIZE, currentAddress, dataLen);
		DWORD unused;
		WriteFile(::hookPipe, buffer, dataLen + HEADER_SIZE, &unused, nullptr);
	}
	hook->ClearHook();
	return 0;
}

int TextHook::InsertReadCode()
{
	hp.hook_len = 0x40;
	//Check if the new hook range conflict with existing ones. Clear older if conflict.
	TextHook *it = hookman;
	for (int i = 0; i < currentHook; it++) {
		if (it->Address())
			i++;
		if (it == this)
			continue;
		if ((it->Address() >= hp.address && it->Address() < hp.hook_len + hp.address) || (it->Address() <= hp.address && it->Address() + it->Length() > hp.address)) 
			it->ClearHook();
	}
	if (!IthGetMemoryRange((LPCVOID)hp.address, 0, 0))
	{
		ConsoleOutput("cannot access read address");
		return no;
	}
	hp.readerHandle = CreateThread(nullptr, 0, ReaderThread, this, 0, nullptr);
	return yes;
	
}

int TextHook::InitHook(const HookParam &h, LPCSTR name, WORD set_flag)
{
  WaitForSingleObject(hmMutex, 0);
  hp = h;
  hp.type |= set_flag;
  if (name && name != hook_name) {
	  SetHookName(name);
  }
  currentHook++;
  current_available = this+1;
  while (current_available->Address())
    current_available++;
  ReleaseMutex(hmMutex);
  return 1;
}

int TextHook::RemoveHookCode()
{
  if (!hp.address)
    return no;
  
  DWORD l = hp.hook_len;

  memcpy((void*)hp.address, original, hp.recover_len);
  FlushInstructionCache(GetCurrentProcess(), (void*)hp.address, hp.recover_len);
  return yes;
}

int TextHook::RemoveReadCode()
{
	if (!hp.address) return no;
	TerminateThread(hp.readerHandle, 0);
	CloseHandle(hp.readerHandle);
	return yes;
}

int TextHook::ClearHook()
{
  int err;
  WaitForSingleObject(hmMutex, 0);
  ConsoleOutput("vnrcli:RemoveHook: enter");
  if (hp.type & DIRECT_READ) err = RemoveReadCode();
  else err = RemoveHookCode();
  NotifyHookRemove(hp.address);
  if (hook_name) {
    delete[] hook_name;
    hook_name = nullptr;
  }
  memset(this, 0, sizeof(TextHook)); // jichi 11/30/2013: This is the original code of ITH
  //if (current_available>this)
  //  current_available = this;
  currentHook--;
  ConsoleOutput("vnrcli:RemoveHook: leave");
  ReleaseMutex(hmMutex);
  return err;
}

int TextHook::SetHookName(LPCSTR name)
{
  name_length = strlen(name) + 1;
  if (hook_name)
    delete[] hook_name;
  hook_name = new char[name_length];
  //ITH_MEMSET_HEAP(hook_name, 0, sizeof(wchar_t) * name_length); // jichi 9/26/2013: zero memory
  strcpy(hook_name, name);
  return 0;
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

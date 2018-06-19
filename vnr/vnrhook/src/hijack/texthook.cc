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

static bool IsGDIFunction(LPCVOID addr)
{
  static LPVOID funcs[] = { HOOK_GDI_FUNCTION_LIST };
  for (size_t i = 0; i < sizeof(funcs)/sizeof(*funcs); i++)
    if (addr == funcs[i])
      return true;
  return false;
}

//FilterRange filter[8];

DWORD flag,
      enter_count;

TextHook *hookman,
         *current_available;

// - Unnamed helpers -

namespace { // unnamed
//provide const time hook entry.
int userhook_count;

#if 0 // 3/6/2015 jichi: this hook is not used and hence disabled
const byte common_hook2[] = {
  0x89, 0x3c,0xe4, // mov [esp],edi
  0x60, // pushad
  0x9c, // pushfd
  0x8d,0x54,0x24,0x28, // lea edx,[esp+0x28] ; esp value
  0x8b,0x32,     // mov esi,[edx] ; return address
  0xb9, 0,0,0,0, // mov ecx, $ ; pointer to TextHook
  0xe8, 0,0,0,0, // call @hook
  0x9d, // popfd
  0x61, // popad
  0x5f, // pop edi ; skip return address on stack
}; //...
#endif // 0

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

DWORD GetModuleBase()
{
	__asm
	{
		mov eax, fs:[0x18]
			mov eax, [eax + 0x30]
			mov eax, [eax + 0xc]
			mov eax, [eax + 0xc]
			mov eax, [eax + 0x18]
	}
}

//void NotifyHookInsert()
//{
//  if (live)
//  {
//    BYTE buffer[0x10];
//    *(DWORD*)buffer=-1;
//    *(DWORD*)(buffer+4)=1;
//    IO_STATUS_BLOCK ios;
//    NtWriteFile(hookPipe,0,0,0,&ios,buffer,0x10,0,0);
//  }
//}

__declspec(naked) void SafeExit() // Return to eax
{
  __asm
  {
    mov [esp+0x24], eax
    popfd
    popad
    retn
  }
}

#if 0
// jichi 12/2/2013: This function mostly return 0.
// But sometimes return the hook address from TextHook::Send
__declspec(naked) // jichi 10/2/2013: No prolog and epilog
int ProcessHook(DWORD dwDataBase, DWORD dwRetn, TextHook *hook) // Use SEH to ensure normal execution even bad hook inserted.
{
  //with_seh(hook->Send(dwDataBase, dwRetn));
  seh_push_(seh_exit, 0, eax, ebx) // jichi 12/13/2013: only eax and ebx are available. ecx and edx are used.
  __asm
  {
    push esi
    push edx
    call TextHook::UnsafeSend
    test eax, eax
    jz seh_exit   // label in seh_pop
    mov ecx, SafeExit
    mov [esp + 8], ecx // jichi 12/13/2013: change exit point if Send returns non-zero, not + 8 beause two elements has been pused
  }
  seh_pop_(seh_exit)
  __asm retn    // jichi 12/13/2013: return near, see: http://stackoverflow.com/questions/1396909/ret-retn-retf-how-to-use-them
}
#endif // 0

#if 1
__declspec(naked) // jichi 10/2/2013: No prolog and epilog
int ProcessHook(DWORD dwDataBase, DWORD dwRetn, TextHook *hook) // Use SEH to ensure normal execution even bad hook inserted.
{
  // jichi 12/17/2013: The function parameters here are meaning leass. The parameters are in esi and edi
  __asm
  {
    push esi
    push edx
    call TextHook::Send
    test eax, eax
    jz ok   // label in seh_pop
    mov ecx, SafeExit
    mov [esp], ecx // jichi 12/13/2013: change exit point if Send returns non-zero
  ok:
    retn    // jichi 12/13/2013: return near, see: http://stackoverflow.com/questions/1396909/ret-retn-retf-how-to-use-them
  }
}
#endif // 1

// Return false if all text are ascii
bool NoAsciiFilter(LPVOID data, DWORD *size, HookParam *, BYTE)
{
  auto text = reinterpret_cast<LPBYTE>(data);
  if (text)
    for (size_t i = 0; i < *size; i++)
      if (text[i] > 127)
        return true;
  return false;
}

} // unnamed namespace

// - TextHook methods -

// jichi 12/2/2013: This function mostly return 0.
// It return the hook address only for auxiliary case.
// However, because no known hooks are auxiliary, this function always return 0.
//
// jichi 5/11/2014:
// - dwDataBase: the stack address
// - dwRetn: the return address of the hook
DWORD TextHook::Send(DWORD dwDataBase, DWORD dwRetn)
{
  // jich: 6/17/2015: do not send when ctrl/shift are controlled
  //if (WinKey::isKeyControlPressed() || WinKey::isKeyShiftPressed() && !WinKey::isKeyReturnPressed())
  //  return 0;

  DWORD ret = 0;
  //char b[0x100];
  //::wcstombs(b, hook_name, 0x100);
  //ConsoleOutput(b);
  ITH_WITH_SEH(ret = UnsafeSend(dwDataBase, dwRetn));
  return ret;
}

DWORD TextHook::UnsafeSend(DWORD dwDataBase, DWORD dwRetn)
{
  enum { SMALL_BUFF_SIZE = 0x80 };
  enum { MAX_DATA_SIZE = 0x10000 }; // jichi 12/25/2013: The same as the original ITH
  DWORD dwCount,
      dwAddr,
      dwDataIn,
      dwSplit;
  BYTE *pbData,
       pbSmallBuff[SMALL_BUFF_SIZE];
  DWORD dwType = hp.type;
  if (!::live) // the pipe thread is busy
    return 0;
  //if ((dwType & NO_CONTEXT) == 0 && HookFilter(dwRetn))
  //  return 0;

  if ((dwType & NO_ASCII) && !hp.filter_fun)
    hp.filter_fun = NoAsciiFilter;

  // jichi 10/24/2014: Skip GDI functions 
  // Artikash 6/3/2018: ^ why??
  // Artikash 6/3/2018: Reenable GDI functions
  //if (!::gdi_hook_enabled_ && ::IsGDIFunction((LPCVOID)hp.address))
  //  return 0;

  dwAddr = hp.address;

  /** jichi 12/24/2014
   *  @param  addr  function address
   *  @param  frame  real address of the function, supposed to be the same as addr
   *  @param  stack  address of current stack - 4
   *  @return  If success, which is reverted
   */
  if (::trigger)
    ::trigger = Engine::InsertDynamicHook((LPVOID)dwAddr, *(DWORD *)(dwDataBase - 0x1c), *(DWORD *)(dwDataBase-0x18));
  // jichi 10/21/2014: Directly invoke engine functions.
  //if (trigger) {
  //  if (InsertDynamicHook)
  //    trigger = InsertDynamicHook((LPVOID)dwAddr, *(DWORD *)(dwDataBase - 0x1c), *(DWORD *)(dwDataBase-0x18));
  //  else
  //    trigger = 0;
  //}
#if 0 // diasble HOOK_AUXILIARY
  // jichi 12/13/2013: None of known hooks are auxiliary
  if (dwType & HOOK_AUXILIARY) {
    //Clean hook when dynamic hook finished.
    //AUX hook is only used for a foothold of dynamic hook.
    if (!trigger) {
      ClearHook();
      // jichi 12/13/2013: This is the only place where this function could return non-zero value
      // However, I non of the known hooks are auxiliary
      return dwAddr;
    }
    return 0;
  }
#endif // 0
  // jichi 10/24/2014: generic hook function
  if (hp.hook_fun && !hp.hook_fun(dwDataBase, &hp))
    hp.hook_fun = nullptr;

  if (dwType & HOOK_EMPTY) // jichi 10/24/2014: dummy hook only for dynamic hook
    return 0;

  // jichi 2/2/2015: Send multiple texts
  for (BYTE textIndex = 0; textIndex <= hp.extra_text_count; textIndex++) {
    dwCount = 0;
    dwSplit = 0;
    dwDataIn = *(DWORD *)(dwDataBase + hp.offset); // default value

    //if (dwType & EXTERN_HOOK) {
    if (hp.text_fun) {  // jichi 10/24/2014: remove EXTERN_HOOK
      //DataFun fun=(DataFun)hp.text_fun;
      //auto fun = hp.text_fun;
      hp.text_fun(dwDataBase, &hp, textIndex, &dwDataIn, &dwSplit, &dwCount);
      //if (dwCount == 0 || dwCount > MAX_DATA_SIZE)
      //  return 0;
      if (dwSplit && (dwType & RELATIVE_SPLIT) && dwSplit > ::processStartAddress)
        dwSplit -= ::processStartAddress;
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
        if (dwSplit && (dwType & RELATIVE_SPLIT) && dwSplit > ::processStartAddress)
          dwSplit -= ::processStartAddress;
      }
      if (dwType & DATA_INDIRECT) {
        if (IthGetMemoryRange((LPVOID)(dwDataIn + hp.index), 0, 0))
          dwDataIn = *(DWORD *)(dwDataIn + hp.index);
        else
          return 0;
      }
      //if (dwType & PRINT_DWORD) {
      //  swprintf((WCHAR *)(pbSmallBuff + HEADER_SIZE), L"%.8X ", dwDataIn);
      //  dwDataIn = (DWORD)pbSmallBuff + HEADER_SIZE;
      //}
      dwCount = GetLength(dwDataBase, dwDataIn);
    }

    // jichi 12/25/2013: validate data size
    if (dwCount == 0 || dwCount > MAX_DATA_SIZE)
      return 0;

    size_t sz = dwCount + HEADER_SIZE;
    if (sz >= SMALL_BUFF_SIZE)
      pbData = new BYTE[sz];
      //ITH_MEMSET_HEAP(pbData, 0, sz * sizeof(BYTE)); // jichi 9/26/2013: zero memory
    else
      pbData = pbSmallBuff;

    if (hp.length_offset == 1) {
      if (dwType & STRING_LAST_CHAR) {
        LPWSTR ts = (LPWSTR)dwDataIn;
        dwDataIn = ts[::wcslen(ts) -1];
      }
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
    if (hp.filter_fun && !hp.filter_fun(pbData + HEADER_SIZE, &dwCount, &hp, textIndex) || dwCount <= 0) {
      if (pbData != pbSmallBuff)
        delete[] pbData;
      return 0;
    }

    *(DWORD *)pbData = dwAddr;
    if (dwType & (NO_CONTEXT|FIXING_SPLIT))
      dwRetn = 0;
    else if (dwRetn && (dwType & RELATIVE_SPLIT))
      dwRetn -= ::processStartAddress;

    *((DWORD *)pbData + 1) = dwRetn;
    *((DWORD *)pbData + 2) = dwSplit;
    if (dwCount) {
      IO_STATUS_BLOCK ios = {};

      //CliLockPipe();
	  WriteFile(::hookPipe, pbData, dwCount + HEADER_SIZE, nullptr, nullptr);
      //CliUnlockPipe();
    }
    if (pbData != pbSmallBuff)
      delete[] pbData;
  }
  return 0;

}

int TextHook::InsertHook()
{
  //ConsoleOutput("vnrcli:InsertHook: enter");
  WaitForSingleObject(hmMutex, 0);
  int ok = InsertHookCode();
  ReleaseMutex(hmMutex);
  if (hp.type & HOOK_ADDITIONAL) {
    NotifyHookInsert(hp.address);
    //ConsoleOutput(hook_name);
    //RegisterHookName(hook_name,hp.address);
  }
  //ConsoleOutput("vnrcli:InsertHook: leave");
  return ok;
}

int TextHook::InsertHookCode()
{
  enum : int { yes = 0, no = 1 };
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
  enum : int { yes = 0, no = 1 };
  // MODULE_OFFSET is set, but there's no module address
  // this means that this is an absolute address found on Windows 2000/XP
  // we make the address relative to the process base
  // we also store the original address in the function field because normally there can not
  // exist a function address without a module address
  if (hp.type & MODULE_OFFSET && !hp.module) {
    DWORD base = GetModuleBase();
    hp.function = hp.address;
    hp.address -= 0x400000;
    hp.address += base;
    hp.type &= ~MODULE_OFFSET;
  }
  else if (hp.module && (hp.type & MODULE_OFFSET)) { // Map hook offset to real address.
    if (DWORD base = GetModuleBase(hp.module)) {
      if (hp.function && (hp.type & FUNCTION_OFFSET)) {
        base = GetExportAddress(base, hp.function);
        if (base)
          hp.address += base;
        else {
          currentHook--;
          ConsoleOutput("vnrcli:UnsafeInsertHookCode: FAILED: function not found in the export table");
          return no;
        }
      }
      else {
        hp.address += base;
      }
      hp.type &= ~(MODULE_OFFSET | FUNCTION_OFFSET);
    }
    else {
      currentHook--;
      ConsoleOutput("vnrcli:UnsafeInsertHookCode: FAILED: module not present");
      return no;
    }
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
  MEMORY_BASIC_INFORMATION info = {};
  NtQueryVirtualMemory(GetCurrentProcess(), (LPVOID)hp.address, MemoryBasicInformation, &info, sizeof(info), nullptr);
  if (info.Type & PAGE_NOACCESS) {
    ConsoleOutput("vnrcli:UnsafeInsertHookCode: FAILED: page no access");
    return no;
  }

  // Initialize common routine.
  memcpy(recover, common_hook, sizeof(common_hook));
  BYTE *c = (BYTE *)hp.address,
       *r = recover;
  BYTE inst[8]; // jichi 9/27/2013: Why 8? Only 5 bytes will be written using NtWriteVirtualMemory
  inst[0] = 0xe9; // jichi 9/27/2013: 0xe9 is jump, see: http://code.google.com/p/sexyhook/wiki/SEXYHOOK_Hackers_Manual
  __asm
  {
    mov edx,r // r = recover
    mov eax,this
    mov [edx+0xa],eax // push TextHook*, resolve to correspond hook.
    lea eax,[edx+0x13]
    mov edx,ProcessHook
    sub edx,eax
    mov [eax-4],edx // call ProcessHook
    mov eax,c
    add eax,5
    mov edx,r
    sub edx,eax
    lea eax,inst+1
    mov [eax],edx // jichi 12/17/2013: the parameter of jmp is in edx. So, ProcessHook must be naked.
  }
  r += sizeof(common_hook);
  hp.hook_len = 5;
  //bool jmpflag=false; // jichi 9/28/2013: nto used
  // Copy original code.
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
      add edx,[ecx]hp.address
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
  // Insert hook and flush instruction cache.
  enum {c8 = 0xcccccccc};
  DWORD int3[] = {c8, c8};
  DWORD t = 0x100,
      old,
      len;
  // jichi 9/27/2013: Overwrite the memory with inst
  // See: http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtProtectVirtualMemory.html
  // See: http://doxygen.reactos.org/d8/d6b/ndk_2mmfuncs_8h_af942709e0c57981d84586e74621912cd.html
  DWORD addr = hp.address;
  NtProtectVirtualMemory(GetCurrentProcess(), (PVOID *)&addr, &t, PAGE_EXECUTE_READWRITE, &old);
  NtWriteVirtualMemory(GetCurrentProcess(), (BYTE *)hp.address, inst, 5, &t);
  len = hp.recover_len - 5;
  if (len)
    NtWriteVirtualMemory(GetCurrentProcess(), (BYTE *)hp.address + 5, int3, len, &t);
  NtFlushInstructionCache(GetCurrentProcess(), (LPVOID)hp.address, hp.recover_len);
  NtFlushInstructionCache(GetCurrentProcess(), (LPVOID)::hookman, 0x1000);
  //ConsoleOutput("vnrcli:UnsafeInsertHookCode: leave: succeed");
  return 0;
}

int TextHook::InitHook(LPVOID addr, DWORD data, DWORD data_ind,
    DWORD split_off, DWORD split_ind, WORD type, DWORD len_off)
{
  WaitForSingleObject(hmMutex, 0);
  hp.address = (DWORD)addr;
  hp.offset = data;
  hp.index = data_ind;
  hp.split = split_off;
  hp.split_index = split_ind;
  hp.type = type;
  hp.hook_len = 0;
  hp.module = 0;
  hp.length_offset = len_off & 0xffff;
  currentHook++;
  if (current_available >= this)
    for (current_available = this + 1; current_available->Address(); current_available++);
  ReleaseMutex(hmMutex);
  return this - hookman;
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

int TextHook::RemoveHook()
{
  enum : int { yes = 1, no = 0 };
  if (!hp.address)
    return no;
  ConsoleOutput("vnrcli:RemoveHook: enter");
  WaitForSingleObject(hmMutex, TIMEOUT); // jichi 9/28/2012: wait at most for 5 seconds
  DWORD l = hp.hook_len;
  //with_seh({ // jichi 9/17/2013: might crash ><
  // jichi 12/25/2013: Actually, __try cannot catch such kind of exception
  ITH_TRY {
    NtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)hp.address, original, hp.recover_len, &l);
    NtFlushInstructionCache(GetCurrentProcess(), (LPVOID)hp.address, hp.recover_len);
  } ITH_EXCEPT {}
  //});
  hp.hook_len = 0;
  ReleaseMutex(hmMutex);
  ConsoleOutput("vnrcli:RemoveHook: leave");
  return yes;
}

int TextHook::ClearHook()
{
  WaitForSingleObject(hmMutex, 0);
  int err = RemoveHook();
  if (hook_name) {
    delete[] hook_name;
    hook_name = nullptr;
  }
  memset(this, 0, sizeof(TextHook)); // jichi 11/30/2013: This is the original code of ITH
  //if (current_available>this)
  //  current_available = this;
  currentHook--;
  ReleaseMutex(hmMutex);
  return err;
}

int TextHook::ModifyHook(const HookParam &hp)
{
  //WCHAR name[0x40];
  DWORD len = 0;
  if (hook_name)
    len = ::strlen(hook_name);
  LPSTR name = 0;
  if (len) {
    name = new char[len + 1];
    //ITH_MEMSET_HEAP(name, 0, sizeof(wchar_t) * (len + 1)); // jichi 9/26/2013: zero memory
    strcpy(name, hook_name);
  }
  ClearHook();
  InitHook(hp, name);
  InsertHook();
  if (name)
    delete[] name;
  return 0;
}

int TextHook::RecoverHook()
{
  if (hp.address) {
    // jichi 9/28/2013: Only enable TextOutA to debug Cross Channel
    //if (hp.address == (DWORD)TextOutA)
    InsertHook();
    return 1;
  }
  return 0;
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

//typedef void (*DataFun)(DWORD, const HookParam*, DWORD*, DWORD*, DWORD*);

/*
DWORD recv_esp, recv_addr;
EXCEPTION_DISPOSITION ExceptHandler(EXCEPTION_RECORD *ExceptionRecord,
    void *EstablisherFrame, CONTEXT *ContextRecord, void *DispatcherContext)
{
  //WCHAR str[0x40],
  //      name[0x100];
  //ConsoleOutput(L"Exception raised during hook processing.");
  //swprintf(str, L"Exception code: 0x%.8X", ExceptionRecord->ExceptionCode);
  //ConsoleOutput(str);
  //MEMORY_BASIC_INFORMATION info;
  //if (NT_SUCCESS(NtQueryVirtualMemory(GetCurrentProcess(),(PVOID)ContextRecord->Eip,
  //    MemoryBasicInformation,&info,sizeof(info),0)) &&
  //    NT_SUCCESS(NtQueryVirtualMemory(GetCurrentProcess(),(PVOID)ContextRecord->Eip,
  //    MemorySectionName,name,0x200,0))) {
  //  swprintf(str, L"Exception offset: 0x%.8X:%s",
  //      ContextRecord->Eip-(DWORD)info.AllocationBase,
  //      wcsrchr(name,L'\\')+1);
  //  ConsoleOutput(str);
  //}
  ContextRecord->Esp = recv_esp;
  ContextRecord->Eip = recv_addr;
  return ExceptionContinueExecution;
}


//typedef void (*DataFun)(DWORD, const HookParam*, DWORD*, DWORD*, DWORD*);

DWORD recv_esp, recv_addr;
EXCEPTION_DISPOSITION ExceptHandler(EXCEPTION_RECORD *ExceptionRecord,
    void *EstablisherFrame, CONTEXT *ContextRecord, void *DispatcherContext)
{
  //WCHAR str[0x40],
  //      name[0x100];
  //ConsoleOutput(L"Exception raised during hook processing.");
  //swprintf(str, L"Exception code: 0x%.8X", ExceptionRecord->ExceptionCode);
  //ConsoleOutput(str);
  //MEMORY_BASIC_INFORMATION info;
  //if (NT_SUCCESS(NtQueryVirtualMemory(GetCurrentProcess(),(PVOID)ContextRecord->Eip,
  //    MemoryBasicInformation,&info,sizeof(info),0)) &&
  //    NT_SUCCESS(NtQueryVirtualMemory(GetCurrentProcess(),(PVOID)ContextRecord->Eip,
  //    MemorySectionName,name,0x200,0))) {
  //  swprintf(str, L"Exception offset: 0x%.8X:%s",
  //      ContextRecord->Eip-(DWORD)info.AllocationBase,
  //      wcsrchr(name,L'\\')+1);
  //  ConsoleOutput(str);
  //}
  ContextRecord->Esp = recv_esp;
  ContextRecord->Eip = recv_addr;
  return ExceptionContinueExecution;
}

__declspec(naked) // jichi 10/2/2013: No prolog and epilog
int ProcessHook(DWORD dwDataBase, DWORD dwRetn, TextHook *hook) // Use SEH to ensure normal execution even bad hook inserted.
{
  __asm
  {
    mov eax,seh_recover
    mov recv_addr,eax
    push ExceptHandler
    push fs:[0]
    mov recv_esp,esp
    mov fs:[0],esp
    push esi
    push edx
    call TextHook::Send
    test eax,eax
    jz seh_recover
    mov ecx,SafeExit
    mov [esp + 0x8], ecx // change exit point
seh_recover:
    pop dword ptr fs:[0]
    pop ecx
    retn
  }
}
*/

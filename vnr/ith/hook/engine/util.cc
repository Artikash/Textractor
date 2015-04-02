// util/util.cc
// 8/23/2013 jichi
// Branch: ITH_Engine/engine.cpp, revision 133
// See: http://ja.wikipedia.org/wiki/プロジェクト:美少女ゲーム系/ゲームエンジン

#include "engine/util.h"
#include "ith/sys/sys.h"

namespace { // unnamed

// jichi 4/19/2014: Return the integer that can mask the signature
DWORD SigMask(DWORD sig)
{
  __asm
  {
    xor ecx,ecx
    mov eax,sig
_mask:
    shr eax,8
    inc ecx
    test eax,eax
    jnz _mask
    sub ecx,4
    neg ecx
    or eax,-1
    shl ecx,3
    shr eax,cl
  }
}

} // namespace unnamed

// jichi 8/24/2013: binary search?
DWORD Util::GetCodeRange(DWORD hModule,DWORD *low, DWORD *high)
{
  IMAGE_DOS_HEADER *DosHdr;
  IMAGE_NT_HEADERS *NtHdr;
  DWORD dwReadAddr;
  IMAGE_SECTION_HEADER *shdr;
  DosHdr = (IMAGE_DOS_HEADER *)hModule;
  if (IMAGE_DOS_SIGNATURE == DosHdr->e_magic) {
    dwReadAddr = hModule + DosHdr->e_lfanew;
    NtHdr = (IMAGE_NT_HEADERS *)dwReadAddr;
    if (IMAGE_NT_SIGNATURE == NtHdr->Signature) {
      shdr = (PIMAGE_SECTION_HEADER)((DWORD)(&NtHdr->OptionalHeader) + NtHdr->FileHeader.SizeOfOptionalHeader);
      while ((shdr->Characteristics & IMAGE_SCN_CNT_CODE) == 0)
        shdr++;
      *low = hModule + shdr->VirtualAddress;
      *high = *low + (shdr->Misc.VirtualSize & 0xfffff000) + 0x1000;
    }
  }
  return 0;
}

DWORD Util::FindCallAndEntryBoth(DWORD fun, DWORD size, DWORD pt, DWORD sig)
{
  //WCHAR str[0x40];
  enum { reverse_length = 0x800 };
  DWORD t, l;
  DWORD mask = SigMask(sig);
  bool flag2;
  for (DWORD i = 0x1000; i < size-4; i++) {
    bool flag1 = false;
    if (*(BYTE *)(pt + i) == 0xe8) {
      flag1 = flag2 = true;
      t = *(DWORD *)(pt + i + 1);
    } else if (*(WORD *)(pt + i) == 0x15ff) {
      flag1 = true;
      flag2 = false;
      t = *(DWORD *)(pt + i + 2);
    }
    if (flag1) {
      if (flag2) {
        flag1 = (pt + i + 5 + t == fun);
        l = 5;
      } else if (t >= pt && t <= pt + size - 4) {
        flag1 = fun == *(DWORD *)t;
        l = 6;
      } else
        flag1 = false;
      if (flag1)
        //swprintf(str,L"CALL addr: 0x%.8X",pt + i);
        //OutputConsole(str);
        for (DWORD j = i; j > i - reverse_length; j--)
          if ((*(WORD *)(pt + j)) == (sig & mask))  //Fun entry 1.
            //swprintf(str,L"Entry: 0x%.8X",pt + j);
            //OutputConsole(str);
            return pt + j;
      else
        i += l;
    }
  }
  //OutputConsole(L"Find call and entry failed.");
  return 0;
}

DWORD Util::FindCallOrJmpRel(DWORD fun, DWORD size, DWORD pt, bool jmp)
{
  BYTE sig = (jmp) ? 0xe9 : 0xe8;
  for (DWORD i = 0x1000; i < size - 4; i++)
    if (sig == *(BYTE *)(pt + i)) {
      DWORD t = *(DWORD *)(pt + i + 1);
      if(fun == pt + i + 5 + t)
        //OutputDWORD(pt + i);
        return pt + i;
      else
        i += 5;
    }
  return 0;
}

DWORD Util::FindCallOrJmpAbs(DWORD fun, DWORD size, DWORD pt, bool jmp)
{
  WORD sig = jmp ? 0x25ff : 0x15ff;
  for (DWORD i = 0x1000; i < size - 4; i++)
    if (sig == *(WORD *)(pt + i)) {
      DWORD t = *(DWORD *)(pt + i + 2);
      if (t > pt && t < pt + size) {
        if (fun == *(DWORD *)t)
          return pt + i;
        else
          i += 5;
      }
    }
  return 0;
}

DWORD Util::FindCallBoth(DWORD fun, DWORD size, DWORD pt)
{
  for (DWORD i = 0x1000; i < size - 4; i++) {
    if (*(BYTE *)(pt + i) == 0xe8) {
      DWORD t = *(DWORD *)(pt + i + 1) + pt + i + 5;
      if (t == fun)
        return i;
    }
    if (*(WORD *)(pt + i) == 0x15ff) {
      DWORD t = *(DWORD *)(pt + i + 2);
      if (t >= pt && t <= pt + size - 4) {
        if (*(DWORD *)t == fun)
          return i;
        else
          i += 6;
      }
    }
  }
  return 0;
}

DWORD Util::FindCallAndEntryAbs(DWORD fun, DWORD size, DWORD pt, DWORD sig)
{
  //WCHAR str[0x40];
  enum { reverse_length = 0x800 };
  DWORD mask = SigMask(sig);
  for (DWORD i = 0x1000; i < size - 4; i++)
    if (*(WORD *)(pt + i) == 0x15ff) {
      DWORD t = *(DWORD *)(pt + i + 2);
      if (t >= pt && t <= pt + size - 4) {
        if (*(DWORD *)t == fun)
          //swprintf(str,L"CALL addr: 0x%.8X",pt + i);
          //OutputConsole(str);
          for (DWORD j = i ; j > i - reverse_length; j--)
            if ((*(DWORD *)(pt + j) & mask) == sig) // Fun entry 1.
              //swprintf(str,L"Entry: 0x%.8X",pt + j);
              //OutputConsole(str);
              return pt + j;

      } else
        i += 6;
    }
  //OutputConsole(L"Find call and entry failed.");
  return 0;
}

DWORD Util::FindCallAndEntryRel(DWORD fun, DWORD size, DWORD pt, DWORD sig)
{
  //WCHAR str[0x40];
  enum { reverse_length = 0x800 };
  if (DWORD i = FindCallOrJmpRel(fun, size, pt, false)) {
    DWORD mask = SigMask(sig);
    for (DWORD j = i; j > i - reverse_length; j--)
      if (((*(DWORD *)j) & mask) == sig)  //Fun entry 1.
        //swprintf(str,L"Entry: 0x%.8X",j);
        //OutputConsole(str);
        return j;
      //OutputConsole(L"Find call and entry failed.");
  }
  return 0;
}
DWORD Util::FindEntryAligned(DWORD start, DWORD back_range)
{
  start &= ~0xf;
  for (DWORD i = start, j = start - back_range; i > j; i-=0x10) {
    DWORD k = *(DWORD *)(i-4);
    if (k == 0xcccccccc
      || k == 0x90909090
      || k == 0xccccccc3
      || k == 0x909090c3
      )
      return i;
    DWORD t = k & 0xff0000ff;
    if (t == 0xcc0000c2 || t == 0x900000c2)
      return i;
    k >>= 8;
    if (k == 0xccccc3 || k == 0x9090c3)
      return i;
    t = k & 0xff;
    if (t == 0xc2)
      return i;
    k >>= 8;
    if (k == 0xccc3 || k == 0x90c3)
      return i;
    k >>= 8;
    if (k == 0xc3)
      return i;
  }
  return 0;
}

DWORD Util::FindImportEntry(DWORD hModule, DWORD fun)
{
  IMAGE_DOS_HEADER *DosHdr;
  IMAGE_NT_HEADERS *NtHdr;
  DWORD IAT, end, pt, addr;
  DosHdr = (IMAGE_DOS_HEADER *)hModule;
  if (IMAGE_DOS_SIGNATURE == DosHdr->e_magic) {
    NtHdr = (IMAGE_NT_HEADERS *)(hModule + DosHdr->e_lfanew);
    if (IMAGE_NT_SIGNATURE == NtHdr->Signature) {
      IAT = NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
      end = NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
      IAT += hModule;
      end += IAT;
      for (pt = IAT; pt < end; pt += 4) {
        addr = *(DWORD *)pt;
        if (addr == fun)
          return pt;
      }
    }
  }
  return 0;
}

// Search string in rsrc section. This section usually contains version and copyright info.
bool Util::SearchResourceString(LPCWSTR str)
{
  DWORD hModule = Util::GetModuleBase();
  IMAGE_DOS_HEADER *DosHdr;
  IMAGE_NT_HEADERS *NtHdr;
  DosHdr = (IMAGE_DOS_HEADER *)hModule;
  DWORD rsrc, size;
  //__asm int 3
  if (IMAGE_DOS_SIGNATURE == DosHdr->e_magic) {
    NtHdr = (IMAGE_NT_HEADERS *)(hModule + DosHdr->e_lfanew);
    if (IMAGE_NT_SIGNATURE == NtHdr->Signature) {
      rsrc = NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
      if (rsrc) {
        rsrc += hModule;
        if (IthGetMemoryRange((LPVOID)rsrc, &rsrc ,&size) &&
            SearchPattern(rsrc, size - 4, str, wcslen(str) << 1))
          return true;
      }
    }
  }
  return false;
}

// jichi 4/15/2014: Copied from GetModuleBase in ITH CLI, for debugging purpose
DWORD Util::FindModuleBase(DWORD hash)
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

// EOF

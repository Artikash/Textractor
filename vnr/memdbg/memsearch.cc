// memsearch.cc
// 4/20/2014 jichi
#include "memdbg/memsearch.h"
#include <windows.h>

// Helpers

namespace { // unnamed

enum : BYTE { byte_nop = 0x90 };
enum : BYTE { byte_int3 = 0xcc };
enum : WORD { word_2int3 = 0xcccc };

// jichi 4/19/2014: Return the integer that can mask the signature
DWORD sigMask(DWORD sig)
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

/**
 *  Return the address of the first matched pattern.
 *  The same as ITH SearchPattern(). KMP is used.
 *  Return 0 if failed. The return result is ambiguous if the pattern address is 0.
 *
 *  @param  startAddress  search start address
 *  @param  range  search range
 *  @param  pattern  array of bytes to match
 *  @param  patternSize  size of the pattern array
 *  @return  relative offset from the startAddress
 */
DWORD searchPattern(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length) // KMP
{
  __asm
  {
    mov eax,search_length
alloc:
    push 0
    sub eax,1
    jnz alloc

    mov edi,search
    mov edx,search_length
    mov ecx,1
    xor esi,esi
build_table:
    mov al,byte ptr [edi+esi]
    cmp al,byte ptr [edi+ecx]
    sete al
    test esi,esi
    jz pre
    test al,al
    jnz pre
    mov esi,[esp+esi*4-4]
    jmp build_table
pre:
    test al,al
    jz write_table
    inc esi
write_table:
    mov [esp+ecx*4],esi

    inc ecx
    cmp ecx,edx
    jb build_table

    mov esi,base
    xor edx,edx
    mov ecx,edx
matcher:
    mov al,byte ptr [edi+ecx]
    cmp al,byte ptr [esi+edx]
    sete al
    test ecx,ecx
    jz match
    test al,al
    jnz match
    mov ecx, [esp+ecx*4-4]
    jmp matcher
match:
    test al,al
    jz pre2
    inc ecx
    cmp ecx,search_length
    je finish
pre2:
    inc edx
    cmp edx,base_length // search_length
    jb matcher
    mov edx,search_length
    dec edx
finish:
    mov ecx,search_length
    sub edx,ecx
    lea eax,[edx+1]
    lea ecx,[ecx*4]
    add esp,ecx
  }
}

/**
 * jichi 2/5/2014: The same as SearchPattern except it uses 0xff to match everything
 * According to @Andys, 0xff seldom appears in the source code: http://sakuradite.com/topic/124
 */
DWORD searchPatternEx(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length, BYTE wildcard) // KMP
{
  __asm
  {
    // jichi 2/5/2014 BEGIN
    mov bl,wildcard
    // jichi 2/5/2014 END
    mov eax,search_length
alloc:
    push 0
    sub eax,1
    jnz alloc // jichi 2/5/2014: this will also set %eax to zero

    mov edi,search
    mov edx,search_length
    mov ecx,1
    xor esi,esi
build_table:
    mov al,byte ptr [edi+esi]
    cmp al,byte ptr [edi+ecx]
    sete al
    test esi,esi
    jz pre
    test al,al
    jnz pre
    mov esi,[esp+esi*4-4]
    jmp build_table
pre:
    test al,al
    jz write_table
    inc esi
write_table:
    mov [esp+ecx*4],esi

    inc ecx
    cmp ecx,edx
    jb build_table

    mov esi,base
    xor edx,edx
    mov ecx,edx
matcher:
    mov al,byte ptr [edi+ecx] // search
    // jichi 2/5/2014 BEGIN
    mov bh,al // save loaded byte to reduce cache access. %ah is not used and always zero
    cmp al,bl // %bl is the wildcard byte
    sete al
    test al,al
    jnz wildcard_matched
    mov al,bh // restore the loaded byte
    // jichi 2/5/2014 END
    cmp al,byte ptr [esi+edx] // base
    sete al
    // jichi 2/5/2014 BEGIN
wildcard_matched:
    // jichi 2/5/2014 END
    test ecx,ecx
    jz match
    test al,al
    jnz match
    mov ecx, [esp+ecx*4-4]
    jmp matcher
match:
    test al,al
    jz pre2
    inc ecx
    cmp ecx,search_length
    je finish
pre2:
    inc edx
    cmp edx,base_length // search_length
    jb matcher
    mov edx,search_length
    dec edx
finish:
    mov ecx,search_length
    sub edx,ecx
    lea eax,[edx+1]
    lea ecx,[ecx*4]
    add esp,ecx
  }
}

// Modified from ITH findCallOrJmpAbs
// Example call:
// 00449063  |. ff15 5cf05300  call dword ptr ds:[<&gdi32.getglyphoutli>; \GetGlyphOutlineA
enum : WORD {
  word_jmp = 0x25ff
  , word_call = 0x15ff // far call
};
/***
 *  Return the absolute address of op. Op takes 1 parameter.
 *
 *  @param  op  first half of the operator
 *  @param  arg1  the function address
 *  @param  start address
 *  @param  search range
 *  @return  absolute address or 0
 */
DWORD findWordCall(WORD op, DWORD arg1, DWORD start, DWORD size)
{
  typedef WORD optype;
  typedef DWORD argtype;

  enum { START = 0x1000 }; // leading size to skip
  for (DWORD i = START; i < size - sizeof(argtype); i++)
    if (op == *(optype *)(start + i)) {
      DWORD t = *(DWORD *)(start + i + sizeof(optype));
      if (t > start && t < start + size) {
        if (arg1 == *(argtype *)t)
          return start + i;
        else
          i += sizeof(optype) + sizeof(argtype) - 1; // == 5
      }
    }
  return 0;
}

// Modified from ITH findCallOrJmpAbs
enum : BYTE {
  byte_call = 0xe8 // near call
  , byte_push_small = 0x6a // push byte operand
  , byte_push_large = 0x68 // push operand > 0xff
};

/***
 *  Return the absolute address of op. Op takes 1 address parameter.
 *
 *  @param  op  first half of the operator
 *  @param  arg1  the function address
 *  @param  start address
 *  @param  search range
 *  @return  absolute address or 0
 */
DWORD findByteCall(BYTE op, DWORD arg1, DWORD start, DWORD size)
{
  typedef BYTE optype;
  typedef DWORD argtype;

  enum { START = 0x1000 }; // leading size to skip
  for (DWORD i = START; i < size - sizeof(argtype); i++)
    if (op == *(optype *)(start + i)) {
      DWORD t = *(DWORD *)(start + i + sizeof(optype));
      if (t > start && t < start + size) {
        if (arg1 == *(argtype *)t)
          return start + i;
        else
          i += sizeof(optype) + sizeof(argtype) - 1; // == 4
      }
    }
  return 0;
}

/***
 *  Return the absolute address of op. Op takes 1 parameter.
 *
 *  @param  op  first half of the operator
 *  @param  arg1  the first operand
 *  @param  start address
 *  @param  search range
 *  @return  absolute address or 0
 */
//DWORD findByteOp1(BYTE op, DWORD arg1, DWORD start, DWORD size)
//{
//  typedef BYTE optype;
//  typedef DWORD argtype;
//
//  enum { START = 0x1000 }; // leading size to skip
//  for (DWORD i = START; i < size - sizeof(argtype); i++)
//    if (op == *(optype *)(start + i)) {
//      DWORD t = *(DWORD *)(start + i + sizeof(optype));
//      if (t == arg1) {
//        return start + i;
//      else
//        i += sizeof(optype) + sizeof(argtype) - 1; // == 4
//      }
//    }
//  return 0;
//}

} // namespace unnamed

MEMDBG_BEGIN_NAMESPACE

DWORD findJumpAddress(DWORD funcAddr, DWORD lowerBound, DWORD upperBound)
{ return findWordCall(word_jmp, funcAddr, lowerBound, upperBound - lowerBound); }

DWORD findFarCallAddress(DWORD funcAddr, DWORD lowerBound, DWORD upperBound)
{ return findWordCall(word_call, funcAddr, lowerBound, upperBound - lowerBound); }

DWORD findNearCallAddress(DWORD funcAddr, DWORD lowerBound, DWORD upperBound)
{ return findByteCall(byte_call, funcAddr, lowerBound, upperBound - lowerBound); }

DWORD findPushDwordAddress(DWORD value, DWORD lowerBound, DWORD upperBound)
{
  //value = _byteswap_ulong(value); // swap to bigendian
  const BYTE *p = (BYTE *)&value;
  const BYTE bytes[] = {byte_push_large, p[0], p[1], p[2], p[3]};
  return findBytes(bytes, sizeof(bytes), lowerBound, upperBound);
}

DWORD findPushByteAddress(BYTE value, DWORD lowerBound, DWORD upperBound)
{
  const BYTE bytes[] = {byte_push_small, value};
  return findBytes(bytes, sizeof(bytes), lowerBound, upperBound);
}

DWORD findCallerAddress(DWORD funcAddr, DWORD sig, DWORD lowerBound, DWORD upperBound, DWORD reverseLength)
{
  enum { Start = 0x1000 };
  enum { PatternSize = 4 };
  const DWORD size = upperBound - lowerBound - PatternSize;
  const DWORD fun = (DWORD)funcAddr;
  // Example function call:
  // 00449063  |. ff15 5cf05300  call dword ptr ds:[<&gdi32.getglyphoutli>; \GetGlyphOutlineA
  //WCHAR str[0x40];
  const DWORD mask = sigMask(sig);
  for (DWORD i = Start; i < size; i++)
    if (*(WORD *)(lowerBound + i) == word_call) {
      DWORD t = *(DWORD *)(lowerBound + i + 2);
      if (t >= lowerBound && t <= upperBound - PatternSize) {
        if (*(DWORD *)t == fun)
          //swprintf(str,L"CALL addr: 0x%.8X",lowerBound + i);
          //OutputConsole(str);
          for (DWORD j = i ; j > i - reverseLength; j--)
            if ((*(DWORD *)(lowerBound + j) & mask) == sig) // Fun entry 1.
              //swprintf(str,L"Entry: 0x%.8X",lowerBound + j);
              //OutputConsole(str);
              return lowerBound + j;

      } else
        i += 6;
    }
  //OutputConsole(L"Find call and entry failed.");
  return 0;
}

DWORD findMultiCallerAddress(DWORD funcAddr, const DWORD sigs[], DWORD sigCount, DWORD lowerBound, DWORD upperBound, DWORD reverseLength)
{
  enum { Start = 0x1000 };
  enum { PatternSize = 4 };
  const DWORD size = upperBound - lowerBound - PatternSize;
  const DWORD fun = (DWORD)funcAddr;
  // Example function call:
  // 00449063  |. ff15 5cf05300  call dword ptr ds:[<&gdi32.getglyphoutli>; \GetGlyphOutlineA
  //WCHAR str[0x40];

  enum { MaxSigCount = 0x10 }; // mast be larger than maximum sigCount
  DWORD masks[MaxSigCount];
  for (DWORD k = 0; k < sigCount; k++)
    masks[k] = sigMask(sigs[k]);

  for (DWORD i = Start; i < size; i++)
    if (*(WORD *)(lowerBound + i) == word_call) {
      DWORD t = *(DWORD *)(lowerBound + i + 2);
      if (t >= lowerBound && t <= upperBound - PatternSize) {
        if (*(DWORD *)t == fun)
          //swprintf(str,L"CALL addr: 0x%.8X",lowerBound + i);
          //OutputConsole(str);
          for (DWORD j = i ; j > i - reverseLength; j--) {
            DWORD ret = lowerBound + j,
                  inst = *(DWORD *)ret;
            for (DWORD k = 0; k < sigCount; k++)
              if ((inst & masks[k]) == sigs[k]) // Fun entry 1.
                //swprintf(str,L"Entry: 0x%.8X",lowerBound + j);
                //OutputConsole(str);
                return ret;
          }

      } else
        i += 6;
    }
  //OutputConsole(L"Find call and entry failed.");
  return 0;
}

DWORD findLastCallerAddress(DWORD funcAddr, DWORD sig, DWORD lowerBound, DWORD upperBound, DWORD reverseLength)
{
  enum { Start = 0x1000 };
  enum { PatternSize = 4 };
  const DWORD size = upperBound - lowerBound - PatternSize;
  const DWORD fun = (DWORD)funcAddr;
  //WCHAR str[0x40];
  DWORD ret = 0;
  const DWORD mask = sigMask(sig);
  for (DWORD i = Start; i < size; i++)
    if (*(WORD *)(lowerBound + i) == word_call) {
      DWORD t = *(DWORD *)(lowerBound + i + 2);
      if (t >= lowerBound && t <= upperBound - PatternSize) {
        if (*(DWORD *)t == fun)
          //swprintf(str,L"CALL addr: 0x%.8X",lowerBound + i);
          //OutputConsole(str);
          for (DWORD j = i ; j > i - reverseLength; j--)
            if ((*(DWORD *)(lowerBound + j) & mask) == sig) // Fun entry 1.
              //swprintf(str,L"Entry: 0x%.8X",lowerBound + j);
              //OutputConsole(str);
              ret = lowerBound + j;

      } else
        i += 6;
    }
  //OutputConsole(L"Find call and entry failed.");
  return ret;
}

DWORD findCallerAddressAfterInt3(dword_t funcAddr, dword_t lowerBound, dword_t upperBound, dword_t callerSearchSize)
{
  DWORD addr = findCallerAddress(funcAddr, word_2int3, lowerBound, upperBound, callerSearchSize);
  if (addr)
    while (byte_int3 == *(BYTE *)++addr);
  return addr;
}

DWORD findLastCallerAddressAfterInt3(dword_t funcAddr, dword_t lowerBound, dword_t upperBound, dword_t callerSearchSize)
{
  DWORD addr = findLastCallerAddress(funcAddr, word_2int3, lowerBound, upperBound, callerSearchSize);
  if (addr)
    while (byte_int3 == *(BYTE *)++addr);
  return addr;
}

DWORD findEnclosingAlignedFunction(DWORD start, DWORD back_range)
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

DWORD findBytes(const void *pattern, DWORD patternSize, DWORD lowerBound, DWORD upperBound)
{
  DWORD reladdr = searchPattern(lowerBound, upperBound - lowerBound, pattern, patternSize);
  return reladdr ? lowerBound + reladdr : 0;
}

DWORD matchBytes(const void *pattern, DWORD patternSize, DWORD lowerBound, DWORD upperBound, BYTE wildcard)
{
  DWORD reladdr = searchPatternEx(lowerBound, upperBound - lowerBound, pattern, patternSize, wildcard);
  return reladdr ? lowerBound + reladdr : 0;
}

#if 0 // not used
DWORD findBytesInPages(const void *pattern, DWORD patternSize, DWORD lowerBound, DWORD upperBound, SearchType search)
{
  //enum { MinPageSize = 4 * 1024 }; // 4k
  DWORD ret = 0;
  DWORD start = lowerBound,
        stop = start;
  MEMORY_BASIC_INFORMATION mbi = {};

  //lowerBound = 0x10000000;
  //upperBound = 0x14000000;
  //SIZE_T ok = ::VirtualQuery((LPCVOID)lowerBound, &mbi, sizeof(mbi));
  //ITH_GROWL_DWORD7(1, start, stop, mbi.RegionSize, mbi.Protect, mbi.Type, mbi.State);
  //return matchBytes(pattern, patternSize, lowerBound, upperBound, wildcard);
  while (stop < upperBound) {
    SIZE_T ok = ::VirtualQuery((LPCVOID)start, &mbi, sizeof(mbi));
    if (!mbi.RegionSize)
      break;
    // Only visit readable and committed region
    // Protect could be zero if not allowed to query
    if (!ok || !mbi.Protect || mbi.Protect&PAGE_NOACCESS) {
      if (stop > start && (ret = findBytes(pattern, patternSize, lowerBound, upperBound)))
        return ret;
      if (search != SearchAll)
        return 0;
      stop += mbi.RegionSize;
      start = stop;
    } else
      stop += mbi.RegionSize;
  }
  if (stop > start)
    ret = findBytes(pattern, patternSize, start, min(upperBound, stop));
  return ret;
}

DWORD matchBytesInPages(const void *pattern, DWORD patternSize, DWORD lowerBound, DWORD upperBound, BYTE wildcard, SearchType search)
{
  //enum { MinPageSize = 4 * 1024 }; // 4k
  DWORD ret = 0;
  DWORD start = lowerBound,
        stop = start;
  MEMORY_BASIC_INFORMATION mbi = {};

  //lowerBound = 0x10000000;
  //upperBound = 0x14000000;
  //SIZE_T ok = ::VirtualQuery((LPCVOID)lowerBound, &mbi, sizeof(mbi));
  //ITH_GROWL_DWORD7(1, start, stop, mbi.RegionSize, mbi.Protect, mbi.Type, mbi.State);
  //return matchBytes(pattern, patternSize, lowerBound, upperBound, wildcard);
  while (stop < upperBound) {
    SIZE_T ok = ::VirtualQuery((LPCVOID)start, &mbi, sizeof(mbi));
    if (!mbi.RegionSize)
      break;
    // Only visit readable and committed region
    // Protect could be zero if not allowed to query
    if (!ok || !mbi.Protect || mbi.Protect&PAGE_NOACCESS) {
      if (stop > start && (ret = matchBytes(pattern, patternSize, lowerBound, upperBound, wildcard)))
        return ret;
      if (search != SearchAll)
        return 0;
      stop += mbi.RegionSize;
      start = stop;
    } else
      stop += mbi.RegionSize;
  }
  if (stop > start)
    ret = matchBytes(pattern, patternSize, start, min(upperBound, stop), wildcard);
  return ret;
}

#endif // 0

MEMDBG_END_NAMESPACE

// EOF

#if 0 // disabled

/**
 *  Search from stopAddres back to startAddress - range
 *  This function is not well debugged
 */
DWORD reverseSearchPattern(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length) // KMP
{
  __asm
  {
    mov eax,search_length
alloc:
    push 0
    sub eax,1
    jnz alloc

    mov edi,search
    mov edx,search_length
    mov ecx,1
    xor esi,esi
build_table:
    mov al,byte ptr [edi+esi]
    cmp al,byte ptr [edi+ecx]
    sete al
    test esi,esi
    jz pre
    test al,al
    jnz pre
    mov esi,[esp+esi*4-4]
    jmp build_table
pre:
    test al,al
    jz write_table
    inc esi
write_table:
    mov [esp+ecx*4],esi

    inc ecx
    cmp ecx,edx
    jb build_table

    mov esi,base
    xor edx,edx
    mov ecx,edx
matcher:
    mov al,byte ptr [edi+ecx]
    cmp al,byte ptr [esi-edx] // jichi 6/1/2014: The only place that is modified
    sete al
    test ecx,ecx
    jz match
    test al,al
    jnz match
    mov ecx, [esp+ecx*4-4]
    jmp matcher
match:
    test al,al
    jz pre2
    inc ecx
    cmp ecx,search_length
    je finish
pre2:
    inc edx
    cmp edx,base_length // search_length
    jb matcher
    mov edx,search_length
    dec edx
finish:
    mov ecx,search_length
    sub edx,ecx
    lea eax,[edx+1]
    lea ecx,[ecx*4]
    add esp,ecx
  }
}

#endif // 0, disabled


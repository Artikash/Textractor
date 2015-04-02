#ifndef _MEMDBG_MEMSEARCH_H
#define _MEMDBG_MEMSEARCH_H

// memsearch.h
// 4/20/2014 jichi

#include "memdbg/memdbg.h"

MEMDBG_BEGIN_NAMESPACE

/// Estimated maximum size of the caller function, the same as ITH FindCallAndEntryAbs
enum { MaximumFunctionSize = 0x800 };

/**
 *  Return the absolute address of the caller function
 *  The same as ITH FindCallAndEntryAbs().
 *
 *  @param  funcAddr  callee function address
 *  @param  funcInst  the machine code where the caller function starts
 *  @param  lowerBound  the lower memory address to search
 *  @param  upperBound  the upper memory address to search
 *  @param* callerSearchSize  the maximum size of caller
 *  @return  the caller absolute address if succeed or 0 if fail
 *
 *  Example funcInst:
 *  0x55: push ebp
 *  0x81,0xec: sub esp XXOO (0xec81)
 *  0x83,0xec: sub esp XXOO (0xec83)
 */
dword_t findCallerAddress(dword_t funcAddr, dword_t funcInst, dword_t lowerBound, dword_t upperBound, dword_t callerSearchSize = MaximumFunctionSize);
dword_t findCallerAddressAfterInt3(dword_t funcAddr, dword_t lowerBound, dword_t upperBound, dword_t callerSearchSize = MaximumFunctionSize);
dword_t findLastCallerAddress(dword_t funcAddr, dword_t funcInst, dword_t lowerBound, dword_t upperBound, dword_t callerSearchSize = MaximumFunctionSize);
dword_t findLastCallerAddressAfterInt3(dword_t funcAddr, dword_t lowerBound, dword_t upperBound, dword_t callerSearchSize = MaximumFunctionSize);

dword_t findMultiCallerAddress(dword_t funcAddr, const dword_t funcInsts[], dword_t funcInstCount, dword_t lowerBound, dword_t upperBound, dword_t callerSearchSize = MaximumFunctionSize);

/**
 *  Return the absolute address of the long jump (not short jump) instruction address.
 *  The same as ITH FindCallOrJmpAbs(false).
 *
 *  @param  funcAddr  callee function address
 *  @param  lowerBound  the lower memory address to search
 *  @param  upperBound  the upper memory address to search
 *  @return  the call instruction address if succeed or 0 if fail
 */
dword_t findJumpAddress(dword_t funcAddr, dword_t lowerBound, dword_t upperBound);

/**
 *  Return the absolute address of the far call (inter-module) instruction address.
 *  The same as ITH FindCallOrJmpAbs(true).
 *
 *  @param  funcAddr  callee function address
 *  @param  lowerBound  the lower memory address to search
 *  @param  upperBound  the upper memory address to search
 *  @return  the call instruction address if succeed or 0 if fail
 */
dword_t findFarCallAddress(dword_t funcAddr, dword_t lowerBound, dword_t upperBound);

///  Near call (intra-module)
dword_t findNearCallAddress(dword_t funcAddr, dword_t lowerBound, dword_t upperBound);

///  Default to far call
inline dword_t findCallAddress(dword_t funcAddr, dword_t lowerBound, dword_t upperBound)
{ return findFarCallAddress(funcAddr, lowerBound, upperBound); }

///  Push value >= 0xff
dword_t findPushDwordAddress(dword_t value, dword_t lowerBound, dword_t upperBound);

///  Push value <= 0xff
dword_t findPushByteAddress(byte_t value, dword_t lowerBound, dword_t upperBound);

///  Default to push DWORD
inline dword_t findPushAddress(dword_t value, dword_t lowerBound, dword_t upperBound)
{ return findPushDwordAddress(value, lowerBound, upperBound); }

/**
 *  Return the enclosing function address outside the given address.
 *  The same as ITH FindEntryAligned().
 *  "Aligned" here means the function must be after in3 (0xcc) or nop (0x90).
 *
 *  If the function does NOT exist, this function might raise without admin privilege.
 *  It is safer to wrap this function within SEH.
 *
 *  @param  addr  address within th function
 *  @param  searchSize  max backward search size
 *  @return  beginning address of the function
 *  @exception  illegal memory access
 */
dword_t findEnclosingAlignedFunction(dword_t addr, dword_t searchSize = MaximumFunctionSize);

/**
 *  Return the address of the first matched pattern.
 *  Return 0 if failed. The return result is ambiguous if the pattern address is 0.
 *  This function simpily traverse all bytes in memory range and would raise
 *  if no access to the region.
 *
 *  @param  pattern  array of bytes to match
 *  @param  patternSize  size of the pattern array
 *  @param  lowerBound  search start address
 *  @param  upperBound  search stop address
 *  @return  absolute address
 *  @exception  illegal memory access
 */
dword_t findBytes(const void *pattern, dword_t patternSize, dword_t lowerBound, dword_t upperBound);

/**
 *  jichi 2/5/2014: The same as findBytes except it uses widecard to match everything.
 *  The widecard should use the byte seldom appears in the pattern.
 *  See: http://sakuradite.com/topic/124
 *
 *  @param  pattern  array of bytes to match
 *  @param  patternSize  size of the pattern array
 *  @param  lowerBound  search start address
 *  @param  upperBound  search stop address
 *  @param* widecard  the character to match everything
 *  @return  absolute address
 *  @exception  illegal memory access
 */
enum : byte_t { WidecardByte = 0x11 }; // jichi 7/17/2014: 0x11 seldom appear in PSP code pattern
//enum : WORD { WidecardWord = 0xffff };
dword_t matchBytes(const void *pattern, dword_t patternSize, dword_t lowerBound, dword_t upperBound,
                   byte_t wildcard = WidecardByte);

// User space: 0 - 2G (0 - 0x7ffeffff)
// Kernel space: 2G - 4G  (0x80000000 - 0xffffffff)
//
// http://msdn.microsoft.com/en-us/library/windows/hardware/ff560042%28v=vs.85%29.aspx
// http://codesequoia.wordpress.com/2008/11/28/understand-process-address-space-usage/
// http://stackoverflow.com/questions/17244912/open-process-with-debug-privileges-and-read-write-memory
enum MemoryRange : dword_t {
  UserMemoryStartAddress = 0, UserMemoryStopAddress = 0x7ffeffff
  , KernelMemoryStartAddress = 0x80000000, KernelMemoryStopAddress = 0xffffffff
  , MappedMemoryStartAddress = 0x01000000

  , MemoryStartAddress = UserMemoryStartAddress, MemoryStopAddress = UserMemoryStopAddress
};

#if 0 // not used
/**
 *  Traverse memory continues pages and return the address of the first matched pattern.
 *
 *  @param  pattern  array of bytes to match
 *  @param  patternSize  size of the pattern array
 *  @param  lowerBound  search start address
 *  @param  upperBound  search stop address
 *  @param* search  search all pages (SearchAll) or stop on first illegal access (SearchFirst)
 *  @return  absolute address
 */
enum SearchType : byte_t { SearchAll = 0 , SearchFirst };

dword_t findBytesInPages(const void *pattern, dword_t patternSize,
    dword_t lowerBound = MemoryStartAddress, dword_t upperBound = MemoryStopAddress,
    SearchType search = SearchAll);
dword_t matchBytesInPages(const void *pattern, dword_t patternSize,
    dword_t lowerBound = MemoryStartAddress, dword_t upperBound = MemoryStopAddress,
    byte_t wildcard = WidecardByte, SearchType search = SearchAll);

#endif // 0

MEMDBG_END_NAMESPACE

#endif // _MEMDBG_MEMSEARCH_H

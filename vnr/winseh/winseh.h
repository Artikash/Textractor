#pragma once

// winseh.h
// 12/13/2013 jichi
// See: http://code.metager.de/source/xref/WebKit/Source/WebCore/platform/win/makesafeseh.asm
// See: http://jpassing.com/2008/05/20/fun-with-low-level-seh/

#ifdef _MSC_VER
# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#define SEH_RAISE  (*(int*)0 = 0) // raise C000005, for debugging only

// Maximum number of nested SEH
// Default nested function count is 100, see: http://stackoverflow.com/questions/8656089/solution-for-fatal-error-maximum-function-nesting-level-of-100-reached-abor
#ifndef SEH_CAPACITY
# define SEH_CAPACITY   100
#endif // SEH_CAPACITY

enum { seh_capacity = SEH_CAPACITY };

typedef unsigned long seh_dword_t; // DWORD in <windows.h>

// 12/13/2013 jichi
// The list implementation is not thread-safe
extern seh_dword_t seh_esp[seh_capacity], // LPVOID, current stack
                   seh_eip[seh_capacity], // LPVOID, current IP address
                   seh_eh[seh_capacity];  // EXCEPTION_ROUTINE, current exception handler function address
extern seh_dword_t seh_count; // current number of exception handlers
extern seh_dword_t seh_handler; //extern PEXCEPTION_ROUTINE seh_handler;

/**
 *  Push SEH handler
 *  @param  _label  exception recover label which should be the same as seh_pop_
 *  @param  _eh  EXCEPTION_ROUTINE or 0
 *  @param  _r1  scalar register name, such as eax
 *  @param  _r2  counter register name, such as ecx
 *
 *  Note: __asm prefix is needed to allow inlining macro
 *  I didn't pushad and popad which seems to be not needed
 *
 *  For SEH, see:
 *  http://www.codeproject.com/Articles/82701/Win32-Exceptions-OS-Level-Point-of-View
 *  http://sploitfun.blogspot.com/2012/08/seh-exploit-part1.html
 *  http://sploitfun.blogspot.com/2012/08/seh-exploit-part2.html
 *
 *  fs:0x0 on Windows is the pointer to ExceptionList
 *  http://stackoverflow.com/questions/4657661/what-lies-at-fs0x0-on-windows
 *
 *  EPB and ESP
 *  http://stackoverflow.com/questions/1395591/what-is-exactly-the-base-pointer-and-stack-pointer-to-what-do-they-point
 */
#define seh_push_(_label, _eh, _r1, _r2) \
  { \
    __asm mov _r1, _eh /* move new handler address */ \
    __asm mov _r2, seh_count /* get current seh counter */ \
    __asm mov dword ptr seh_eh[_r2*4], _r1 /* set recover exception hander */ \
    __asm mov _r1, _label /* move jump label address */ \
    __asm mov dword ptr seh_eip[_r2*4], _r1 /* set recover eip as the jump label */  \
    __asm push seh_handler /* push new safe seh handler */ \
    __asm push fs:[0] /* push old fs:0 */ \
    __asm mov dword ptr seh_esp[_r2*4], esp /* safe current stack address */ \
    __asm mov fs:[0], esp /* change fs:0 to the current stack */ \
    __asm inc seh_count /* increase number of seh */ \
  }
  //TODO: get sizeof dword instead of hardcode 4

/**
 *  Restore old SEH handler
 *  @param  _label  exception recover label which should be the same as seh_push_
 */
#define seh_pop_(_label) \
  { \
    __asm _label: /* the exception recover label */ \
    __asm pop dword ptr fs:[0] /* restore old fs:0 */ \
    __asm add esp, 4 /* pop seh_handler */ \
    __asm dec seh_count /* decrease number of seh */ \
  }

#define seh_pop()   seh_pop_(seh_exit)
#define seh_push()  seh_push_(seh_exit, 0, eax, ecx) // use ecx as counter better than ebx

/**
 *  @param  _eh  EXCEPTION_ROUTINE or 0
 */
#define seh_push_eh(_eh) seh_push_(seh_exit, _eh, eax, ecx)

/**
 *  Wrap the code block with SEH handler
 *  @param* any code block. The colon for the last expression is optional.
 */
#define seh_with(...) \
  { \
    seh_push() \
    __VA_ARGS__ \
    ; \
    seh_pop() \
  }

/**
 *  Wrap the code block with SEH handler
 *  @param  _eh  EXCEPTION_ROUTINE or 0
 *  @param* any code block. The colon for the last expression is optional.
 */
#define seh_with_eh(_eh, ...) \
  { \
    seh_push_eh(_eh) \
    __VA_ARGS__ \
    ; \
    seh_pop() \
  }

// EOF

//#define seh_push_front() \
//  { \
//    __asm mov eax, seh_exit \
//    __asm mov seh_eip, eax \
//    __asm push seh_handler \
//    __asm push fs:[0] \
//    __asm mov seh_esp, esp \
//    __asm mov fs:[0], esp \
//  }
//
//#define seh_pop_front() \
//  { \
//    __asm seh_exit: \
//    __asm mov eax, [esp] \
//    __asm mov fs:[0], eax \
//    __asm add esp, 8 \
//  }
//
//#define seh_push_back() \
//  { \
//    __asm mov eax, seh_exit \
//    __asm mov ecx, seh_capacity - 1 \
//    __asm mov DWORD PTR seh_eip[ecx*4], eax \
//    __asm push seh_handler \
//    __asm push fs:[0] \
//    __asm mov DWORD PTR seh_esp[ecx*4], esp \
//    __asm mov fs:[0], esp \
//  }
//
//#define seh_pop_back() \
//  { \
//    __asm seh_exit: \
//    __asm mov eax, [esp] \
//    __asm mov fs:[0], eax \
//    __asm add esp, 8 \
//  }

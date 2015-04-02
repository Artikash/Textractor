#pragma once

// ith/sys.h
// 8/23/2013 jichi
// Branch: ITH/IHF_SYS.h, rev 111

#ifdef _MSC_VER
# pragma warning(disable:4800) // C4800: forcing value to bool
#endif // _MSC_VER

#include "ntdll/ntdll.h"

// jichi 8/24/2013: Why extern "C"? Any specific reason to use C instead of C++ naming?
extern "C" {
//int disasm(BYTE *opcode0);  // jichi 8/15/2013: move disasm to separate file
extern WORD *NlsAnsiCodePage;
int FillRange(LPCWSTR name,DWORD *lower, DWORD *upper);
int MB_WC(char *mb, wchar_t *wc);
//int MB_WC_count(char *mb, int mb_length);
int WC_MB(wchar_t *wc, char *mb);

// jichi 10/1/2013: Return 0 if failed. So, it is ambiguous if the search pattern starts at 0
DWORD SearchPattern(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length); // KMP

// jichi 2/5/2014: The same as SearchPattern except it uses 0xff to match everything
// According to @Andys, 0xff seldom appear in the source code: http://sakuradite.com/topic/124
enum : BYTE { SP_ANY = 0xff };
#define SP_ANY_2 SP_ANY,SP_ANY
#define SP_ANY_3 SP_ANY,SP_ANY,SP_ANY
#define SP_ANY_4 SP_ANY,SP_ANY,SP_ANY,SP_ANY
DWORD SearchPatternEx(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length, BYTE wildcard=SP_ANY);

BOOL IthInitSystemService();
void IthCloseSystemService();
DWORD IthGetMemoryRange(LPCVOID mem, DWORD *base, DWORD *size);
BOOL IthCheckFile(LPCWSTR file);
BOOL IthFindFile(LPCWSTR file);
BOOL IthGetFileInfo(LPCWSTR file, LPVOID info, DWORD size = 0x1000);
BOOL IthCheckFileFullPath(LPCWSTR file);
HANDLE IthCreateFile(LPCWSTR name, DWORD option, DWORD share, DWORD disposition);
HANDLE IthCreateFileInDirectory(LPCWSTR name, HANDLE dir, DWORD option, DWORD share, DWORD disposition);
HANDLE IthCreateDirectory(LPCWSTR name);
HANDLE IthCreateFileFullPath(LPCWSTR fullpath, DWORD option, DWORD share, DWORD disposition);
HANDLE IthPromptCreateFile(DWORD option, DWORD share, DWORD disposition);
HANDLE IthCreateSection(LPCWSTR name, DWORD size, DWORD right);
HANDLE IthCreateEvent(LPCWSTR name, DWORD auto_reset=0, DWORD init_state=0);
HANDLE IthOpenEvent(LPCWSTR name);
void IthSetEvent(HANDLE hEvent);
void IthResetEvent(HANDLE hEvent);
HANDLE IthCreateMutex(LPCWSTR name, BOOL InitialOwner, DWORD *exist=0);
HANDLE IthOpenMutex(LPCWSTR name);
BOOL IthReleaseMutex(HANDLE hMutex);
//DWORD IthWaitForSingleObject(HANDLE hObject, DWORD dwTime);
HANDLE IthCreateThread(LPCVOID start_addr, DWORD param, HANDLE hProc=(HANDLE)-1);
DWORD GetExportAddress(DWORD hModule,DWORD hash);
void IthSleep(int time); // jichi 9/28/2013: in ms
void IthSystemTimeToLocalTime(LARGE_INTEGER *ptime);
void FreeThreadStart(HANDLE hProc);
void CheckThreadStart();
} // extern "C"

#ifdef ITH_HAS_HEAP
extern HANDLE hHeap; // used in ith/common/memory.h
#endif // ITH_HAS_HEAP

extern DWORD current_process_id;
extern DWORD debug;
extern BYTE LeadByteTable[];
extern LPVOID page;
extern BYTE launch_time[];

inline DWORD GetHash(LPSTR str)
{
  DWORD hash = 0;
  //for (; *str; str++)
  while (*str)
    hash = ((hash>>7) | (hash<<25)) + *str++;
  return hash;
}

inline DWORD GetHash(LPCWSTR str)
{
  DWORD hash = 0;
  //for (; *str; str++)
  while (*str)
    hash = ((hash>>7) | (hash<<25)) + *str++;
  return hash;
}

inline void IthBreak()
{ if (debug) __debugbreak(); }

inline LPCWSTR GetMainModulePath()
{
  __asm
  {
    mov eax, fs:[0x30]
    mov eax, [eax + 0xC]
    mov eax, [eax + 0xC]
    mov eax, [eax + 0x28]
  }
}

// jichi 9/28/2013: Add this to lock NtWriteFile in wine
class IthMutexLocker
{
  HANDLE m;
public:
  explicit IthMutexLocker(HANDLE mutex) : m(mutex)
  { NtWaitForSingleObject(m, 0, 0); }

  ~IthMutexLocker() { if (m != INVALID_HANDLE_VALUE) IthReleaseMutex(m); }

  bool locked() const  { return m != INVALID_HANDLE_VALUE; }

  void unlock()  { if (m != INVALID_HANDLE_VALUE) { IthReleaseMutex(m); m = INVALID_HANDLE_VALUE; } }
};

void IthCoolDown();

BOOL IthIsWine();
BOOL IthIsWindowsXp();
//BOOL IthIsWindows8OrGreater(); // not public

/** Get current dll path.
 *  @param  buf
 *  @param  len
 *  @return  length of the path excluding \0
 */
size_t IthGetCurrentModulePath(wchar_t *buf, size_t len);

// EOF

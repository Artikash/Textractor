// sys.cc
// 8/21/2013 jichi
// Branch: ITH_SYS/SYS.cpp, rev 126
//
// 8/24/2013 TODO:
// - Clean up the code
// - Move my old create remote thread for ITH2 here

#include "ith/sys/sys.h"
//#include "ith/common/growl.h"
//#include "ith/common/except.h"

//#define ITH_SYS_SECTION L"ITH_SysSection"
#define ITH_THREADMAN_SECTION L"VNR_SYS_THREAD"

// jichi 9/28/2013: Weither use NtThread or RemoteThread
// RemoteThread works on both Windows 7 or Wine, while NtThread does not work on wine
#define ITH_ENABLE_THREADMAN    (!IthIsWindows8OrGreater() && !IthIsWine())
//#define ITH_ENABLE_THREADMAN    true

// Helpers

// jichi 2/3/2015: About GetVersion
// Windows XP SP3: 5.1
// Windows 7: 6.1, 0x1db10106
// Windows 8: 6.2, 0x23f00206
// Windows 10: 6.2, 0x23f00206 (build 9926):

BOOL IthIsWindowsXp()
{
  static BOOL ret = -1; // cached
  if (ret < 0) {
    // http://msdn.microsoft.com/en-us/library/windows/desktop/ms724439%28v=vs.85%29.aspx
    DWORD v = ::GetVersion();
    BYTE major = LOBYTE(LOWORD(v));
    //DWORD minor = (DWORD)(HIBYTE(LOWORD(v)));

    // Windows XP = 5.1
    //ret =  major < 6 ? 1 : 0;
    ret = major < 6;
  }
  return ret;
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/dn424972%28v=vs.85%29.aspx
// The same as IsWindows8OrGreater, which I don't know if the function is available to lower Windows.
static BOOL IthIsWindows8OrGreater() // this function is not exported
{
  static BOOL ret = -1; // cached
  if (ret < 0) {
    // http://msdn.microsoft.com/en-us/library/windows/desktop/ms724439%28v=vs.85%29.aspx
    DWORD v = ::GetVersion();
    BYTE major = LOBYTE(LOWORD(v)),
         minor = HIBYTE(LOWORD(v));
    //DWORD minor = (DWORD)(HIBYTE(LOWORD(v)));

    // Windows 8/10 = 6.2
    ret = major > 6 || (major == 6 && minor >= 2);
  }
  return ret;
}

BOOL IthIsWine()
{
  static BOOL ret = -1; // cached
  if (ret < 0) {
    const wchar_t *path;
    wchar_t buffer[MAX_PATH];
    if (UINT sz = ::GetSystemDirectoryW(buffer, MAX_PATH)) {
      path = buffer;
      ::wcscpy(buffer + sz, L"\\winecfg.exe");
    } else
      path = L"C:\\Windows\\System32\\winecfg.exe";
    //ITH_MSG(path);
    ret = ::GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES ? TRUE : FALSE;
  }
  return ret;
}

// jichi 9/28/2013: prevent parallelization in wine
void IthCoolDown()
{
  // http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtDelayExecution.html
  //const LONGLONG timeout = -10000; // in 100ns, i.e. 1ms
  //NtDelayExecution(FALSE, (PLARGE_INTEGER)&timeout);
  //NtFlushInstructionCache(NtCurrentProcess(), (LPVOID)hp.addr, hp.recover_len);
  // Flush the instruction cache line, and prevent wine from rending things in parallel
  if (IthIsWine())
    IthSleep(1); // sleep for 1 ms
  //__asm
  //{
  //  //mov eax,0x2710    // = 10000
  //  mov ecx,time
  //  mul ecx
  //  neg eax
  //  adc edx,0
  //  neg edx
  //  push edx
  //  push eax
  //  push esp
  //  push 0
  //  call dword ptr [NtDelayExecution]
  //  add esp,8
  //}
}

// jichi 9/23/2013: wine deficenciy on mapping sections
// Whe set to false, do not map sections.
//static bool ith_has_section = true;

//#ifdef ITH_WINE
//# include "winddk/winddk.h"
//#endif // ITH_WINE

//#define SEC_BASED 0x200000    // jichi 8/24/2013: emoved

// jichi 10/6/2013
// See: http://stackoverflow.com/questions/557081/how-do-i-get-the-hmodule-for-the-currently-executing-code
// See: http://www.codeproject.com/Articles/16598/Get-Your-DLL-s-Path-Name
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
#define CURRENT_MODULE_HANDLE  ((HINSTANCE)&__ImageBase)
size_t IthGetCurrentModulePath(wchar_t *buf, size_t len)
{ return ::GetModuleFileNameW(CURRENT_MODULE_HANDLE, buf, len); }

// - Global variables -

#ifdef ITH_HAS_HEAP
HANDLE hHeap; // used in ith/common/memory.h
#endif // ITH_HAS_HEAP

DWORD current_process_id;
DWORD debug;
BYTE launch_time[0x10];
LPVOID page;

BYTE LeadByteTable[0x100] = {
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1
};

namespace { // unnamed

WCHAR file_path[MAX_PATH] = L"\\??\\";
LPWSTR current_dir;
DWORD page_locale;
HANDLE root_obj,
       dir_obj,
       codepage_section,
       thread_man_section;

BYTE file_info[0x1000];


// - Helper functions -

inline DWORD GetShareMemory()
{
  __asm
  {
    mov eax,fs:[0x30]
    mov eax,[eax+0x4C]
  }
}

inline LARGE_INTEGER *GetTimeBias()
{ __asm mov eax,0x7ffe0020 }


//Get full path of current process.
//inline LPWSTR GetModulePath()
//{
//  __asm
//  {
//    mov eax,fs:[0x30]
//    mov eax,[eax+0xC]
//    mov eax,[eax+0xC]
//    mov eax,[eax+0x28]
//  }
//}

// - Singleton classes -

BYTE normal_routine[0x14] = {
  0x51,0x52,0x64,0x89,0x23,0x55,0xff,0xd0,0x50,0x6a,0xfe,0xff,0x15,0x14,0x00,0x00,0x00
};

BYTE except_routine[0xe0] = {
  0xba,0x08,0x00,0x00,0x00,0x8b,0xc1,0x83,0xe0,0x0f,0x83,0xf8,0x0a,0x72,0x02,0x04,
  0x07,0x04,0x30,0x66,0xab,0xc1,0xc9,0x04,0x4a,0x75,0xea,0xc3,0x00,0x00,0x00,0x00,
  0x8b,0x44,0xe4,0x04,0x31,0xf6,0x8b,0x28,0x8b,0x4c,0xe4,0x0c,0x8b,0x99,0xb8,0x00,
  0x00,0x00,0x81,0xec,0x40,0x02,0x00,0x00,0x8d,0x7c,0xe4,0x40,0x89,0xe0,0x56,0x6a,
  0x1c,0x50,0x56,0x53,0x6a,0xff,0xff,0x15,0x18,0x00,0x00,0x00,0x85,0xc0,0x75,0x98,
  0x89,0xe0,0x50,0x68,0x00,0x02,0x00,0x00,0x57,0x6a,0x02,0x53,0x6a,0xff,0xff,0x15,
  0x18,0x00,0x00,0x00,0x85,0xc0,0x75,0xe6,0x5e,0x0f,0xc1,0xf7,0xfd,0xb0,0x5c,0x66,
  0xf2,0xaf,0x66,0xc7,0x47,0x02,0x3a,0x00,0x89,0xd9,0x2b,0x0c,0xe4,0xe8,0x7e,0xff,
  0xff,0xff,0x47,0x47,0x87,0xfe,0x89,0xe9,0xe8,0x73,0xff,0xff,0xff,0x47,0x47,0x31,
  0xc0,0x89,0x47,0x10,0x6a,0x00,0x57,0x56,0x6a,0x00,0xfc,0xff,0x15,0x1c,0x00,0x00,
  0x00,0x83,0xc8,0xff,0xeb,0xbe
};

// jichi 8/24/2013: Could be initialized using NtMapViewOfSection/ZwMapViewOfSection
// This class cannot have constructor / destructor
struct _ThreadView {
  UINT_PTR mutex,
           count;
  DWORD proc_record[1];
};

class : private _ThreadView { // ThreadStartManager

  enum {
    ADDR0 = 0xD
    , ADDR1 = 0x48
    , ADDR2 = 0x60
    , ADDR3 = 0x9D
  };

public:
  LPVOID GetProcAddr(HANDLE hProc)
  {
    AcquireLock();
    DWORD pid,addr,len;
    if (hProc == NtCurrentProcess())
      pid = ::current_process_id;
    else {
      PROCESS_BASIC_INFORMATION info;
      NtQueryInformationProcess(hProc, ProcessBasicInformation, &info, sizeof(info), &len);
      pid=info.uUniqueProcessId;
    }
    pid >>= 2;
    for (UINT_PTR i = 0; i < count; i++)
      if (pid == (proc_record[i] & 0xfff)) {
        addr = proc_record[i] & ~0xfff;
        ReleaseLock();
        return (LPVOID)addr;
      }
    len = 0x1000;
    NtAllocateVirtualMemory(hProc, (PVOID *)(proc_record + count), 0, &len,
        MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    DWORD base = proc_record[count];
    proc_record[count] |= pid;
    union {
      LPVOID buffer;
      DWORD b;
    };
    b = base;
    LPVOID fun_table[3];
    *(DWORD *)(normal_routine + ADDR0) += base;
    NtWriteVirtualMemory(hProc, buffer, normal_routine, 0x14, 0);
    *(DWORD *)(normal_routine + ADDR0) -= base;
    b += 0x14;
    fun_table[0] = NtTerminateThread;
    fun_table[1] = NtQueryVirtualMemory;
    fun_table[2] = MessageBoxW;
    NtWriteVirtualMemory(hProc, buffer, fun_table, 0xC, 0);
    b += 0xc;
    *(DWORD *)(except_routine + ADDR1) += base;
    *(DWORD *)(except_routine + ADDR2) += base;
    *(DWORD *)(except_routine + ADDR3) += base;
    NtWriteVirtualMemory(hProc, buffer, except_routine, 0xE0, 0);
    *(DWORD *)(except_routine + ADDR1) -= base;
    *(DWORD *)(except_routine + ADDR2) -= base;
    *(DWORD *)(except_routine + ADDR3) -= base;
    count++;
    ReleaseLock();
    return (LPVOID)base;
  }
  void ReleaseProcessMemory(HANDLE hProc)
  {
    DWORD pid,addr,len;
    AcquireLock();
    if (hProc==NtCurrentProcess())
      pid = ::current_process_id;
    else {
      PROCESS_BASIC_INFORMATION info;
      NtQueryInformationProcess(hProc,ProcessBasicInformation,&info,sizeof(info),&len);
      pid = info.uUniqueProcessId;
    }
    pid >>= 2;
    //NtWaitForSingleObject(thread_man_mutex,0,0);
    for (UINT_PTR i = 0; i < count; i++) {
      if ((proc_record[i]&0xfff) == pid) {
        addr = proc_record[i] & ~0xfff;
        DWORD size=0x1000;
        NtFreeVirtualMemory(hProc, (PVOID *)&addr, &size, MEM_RELEASE);
        count--;
        for (UINT_PTR j = i; j < count; j++)
          proc_record[j] = proc_record[j + 1];
        proc_record[count] = 0;
        ReleaseLock();
        //NtReleaseMutant(thread_man_mutex,0);
        return;
      }
    }
    ReleaseLock();
    //NtReleaseMutant(thread_man_mutex,0);
  }
  void CheckProcessMemory()
  {
    UINT_PTR i, j, flag, addr;
    DWORD len;
    CLIENT_ID id;
    OBJECT_ATTRIBUTES oa = {};
    HANDLE hProc;
    BYTE buffer[8];
    AcquireLock();
    id.UniqueThread = 0;
    oa.uLength = sizeof(oa);
    for (i = 0; i < count ; i++) {
      id.UniqueProcess = (proc_record[i]&0xfff)<<2;
      addr = proc_record[i] & ~0xfff;
      flag = 0;
      if (NT_SUCCESS(NtOpenProcess(&hProc, PROCESS_VM_OPERATION|PROCESS_VM_READ, &oa, &id))) {
        if (NT_SUCCESS(NtReadVirtualMemory(hProc, (PVOID)addr, buffer, 8, &len)))
          if (::memcmp(buffer, normal_routine, 4) == 0)
            flag = 1;
        NtClose(hProc);
      }
      if (flag == 0) {
        for (j = i; j < count; j++)
          proc_record[j] = proc_record[j + 1];
        count--;
        i--;
      }
    }
    ReleaseLock();
  }
  void AcquireLock()
  {
    LONG *p = (LONG *)&mutex;
    while (_interlockedbittestandset(p,0))
      YieldProcessor();
  }
  void ReleaseLock()
  {
    LONG *p = (LONG*)&mutex;
    _interlockedbittestandreset(p, 0);
  }
} *thread_man_ = nullptr; // global singleton

} // unnamed namespace

// - API functions -

extern "C" {

void FreeThreadStart(HANDLE hProc)
{
  if (thread_man_)
    ::thread_man_->ReleaseProcessMemory(hProc);
}

void CheckThreadStart()
{
  if (thread_man_)
    ::thread_man_->CheckProcessMemory();

    // jichi 2/2/2015: This function is only used to wait for injected threads vnrhost.
    // Sleep for 100 ms to wait for remote thread to start
    //IthSleep(100);
    //IthCoolDown();
}

void IthSleep(int time)
{
  __asm
  {
    mov eax,0x2710 // jichi = 10000
    mov ecx,time
    mul ecx
    neg eax
    adc edx,0
    neg edx
    push edx
    push eax
    push esp
    push 0
    call dword ptr [NtDelayExecution]
    add esp,8
  }
}

void IthSystemTimeToLocalTime(LARGE_INTEGER *time)
{ time->QuadPart -= GetTimeBias()->QuadPart; }

int FillRange(LPCWSTR name, DWORD *lower, DWORD *upper)
{
  PLDR_DATA_TABLE_ENTRY it;
  LIST_ENTRY *begin;
  __asm
  {
    mov eax,fs:[0x30]
    mov eax,[eax+0xc]
    mov eax,[eax+0xc]
    mov it,eax
    mov begin,eax
  }

  while (it->SizeOfImage) {
    if (::_wcsicmp(it->BaseDllName.Buffer, name) == 0) {
      *lower = *upper = (DWORD)it->DllBase;
      MEMORY_BASIC_INFORMATION info = {};
      DWORD l,size;
      size = 0;
      do {
        NtQueryVirtualMemory(NtCurrentProcess(), (LPVOID)(*upper), MemoryBasicInformation, &info, sizeof(info), &l);
        if (info.Protect&PAGE_NOACCESS) {
          it->SizeOfImage=size;
          break;
        }
        size += info.RegionSize;
        *upper += info.RegionSize;
      } while (size < it->SizeOfImage);
      return 1;
    }
    it = (PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink;
    if (it->InLoadOrderModuleList.Flink == begin)
      break;
  }
  return 0;
}

DWORD SearchPattern(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length) // KMP
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

// jichi 2/5/2014: '?' = 0xff
// See: http://sakuradite.com/topic/124
DWORD SearchPatternEx(DWORD base, DWORD base_length, LPCVOID search, DWORD search_length, BYTE wildcard) // KMP
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

DWORD IthGetMemoryRange(LPCVOID mem, DWORD *base, DWORD *size)
{
  DWORD r;
  MEMORY_BASIC_INFORMATION info;
  NtQueryVirtualMemory(NtCurrentProcess(), const_cast<LPVOID>(mem), MemoryBasicInformation, &info, sizeof(info), &r);
  if (base)
    *base = (DWORD)info.BaseAddress;
  if (size)
    *size = info.RegionSize;
  return (info.Type&PAGE_NOACCESS) == 0;
}

// jichi 9/25/2013
// See: http://publib.boulder.ibm.com/infocenter/pseries/v5r3/index.jsp?topic=/com.ibm.aix.nls/doc/nlsgdrf/multi-byte_widechar_subr.htm
// SJIS->Unicode. 'mb' must be null-terminated. 'wc' should have enough space ( 2*strlen(mb) is safe).
//#ifdef ITH_WINE
//int MB_WC(char *mb, wchar_t *wc)
//{ return mbstowcs(wc, mb, 0x100); }
//
//#else
int MB_WC(char *mb, wchar_t *wc)
{
  __asm
  {
    mov esi,mb
    mov edi,wc
    mov edx,page
    lea ebx,LeadByteTable
    add edx,0x220
    push 0
_mb_translate:
    movzx eax,word ptr [esi]
    test al,al
    jz _mb_fin
    movzx ecx,al
    xlat
    test al,1
    cmovnz cx, word ptr [ecx*2+edx-0x204]
    jnz _mb_next
    mov cx,word ptr [ecx*2+edx]
    mov cl,ah
    mov cx, word ptr [ecx*2+edx]
_mb_next:
    mov [edi],cx
    add edi,2
    movzx eax,al
    add esi,eax
    inc dword ptr [esp]
    jmp _mb_translate
_mb_fin:
    pop eax
  }
}

// Count characters of 'mb' string. 'mb_length' is max length.
// jichi 9/25/2013: This function is not used
//int MB_WC_count(char *mb, int mb_length)
//{
//  __asm
//  {
//    xor eax,eax
//    xor edx,edx
//    mov esi,mb
//    mov edi,mb_length
//    lea ebx,LeadByteTable
//_mbc_count:
//    mov dl,byte ptr [esi]
//    test dl,dl
//    jz _mbc_finish
//    movzx ecx, byte ptr [ebx+edx]
//    add esi,ecx
//    inc eax
//    sub edi,ecx
//    ja _mbc_count
//_mbc_finish:
//  }
//}

// jichi 9/25/2013
// See: http://publib.boulder.ibm.com/infocenter/pseries/v5r3/index.jsp?topic=/com.ibm.aix.nls/doc/nlsgdrf/multi-byte_widechar_subr.htm
// Unicode->SJIS. Analogous to MB_WC.
//#ifdef ITH_WINE
//int WC_MB(wchar_t *wc, char *mb)
//{ return wcstombs(mb, wc, 0x100); }
//
//#else
int WC_MB(wchar_t *wc, char *mb)
{
  __asm
  {
    mov esi,wc
    mov edi,mb
    mov edx,page
    add edx,0x7C22
    xor ebx,ebx
_wc_translate:
    movzx eax,word ptr [esi]
    test eax,eax
    jz _wc_fin
    mov cx,word ptr [eax*2+edx]
    test ch,ch
    jz _wc_single
    mov [edi+ebx],ch
    inc ebx
_wc_single:
    mov [edi+ebx],cl
    inc ebx
    add esi,2
    jmp _wc_translate
_wc_fin:
    mov eax,ebx
  }
}

//Initialize environment for NT native calls. Not thread safe so only call it once in one module.
//1. Create new heap. Future memory requests are handled by this heap.
//Destroying this heap will completely release all dynamically allocated memory, thus prevent memory leaks on unload.
//2. Create handle to root directory of process objects (section/event/mutex/semaphore).
//NtCreate* calls will use this handle as base directory.
//3. Load SJIS code page. First check for Japanese locale. If not then load from 'C_932.nls' in system folder.
//MB_WC & WC_MB use this code page for translation.
//4. Locate current NT path (start with \??\).
//NtCreateFile requires full path or a root handle. But this handle is different from object.
//5. Map shared memory for ThreadStartManager into virtual address space.
//This will allow IthCreateThread function properly.
BOOL IthInitSystemService()
{
  PPEB peb;
  //NTSTATUS status;
  DWORD size;
  ULONG LowFragmentHeap;
  UNICODE_STRING us;
  OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  IO_STATUS_BLOCK ios;
  HANDLE codepage_file;
  LARGE_INTEGER sec_size = {0x1000, 0};
  __asm
  {
    mov eax,fs:[0x18]
    mov ecx,[eax+0x20]
    mov eax,[eax+0x30]
    mov peb,eax
    mov current_process_id,ecx
  }
  debug = peb->BeingDebugged;
  LowFragmentHeap = 2;

#ifdef ITH_HAS_HEAP
  ::hHeap = RtlCreateHeap(0x1002, 0, 0, 0, 0, 0);
  RtlSetHeapInformation(::hHeap, HeapCompatibilityInformation, &LowFragmentHeap, sizeof(LowFragmentHeap));
#endif // ITH_HAS_HEAP

  LPWSTR t = nullptr,   // jichi: path to system32, such as "c:\windows\system32"
         obj = nullptr; // jichi: path to current kernel session, such as "Sessions\\1\\BaseNamedObjects"
  // jichi 9/22/2013: This would crash wine with access violation exception.
  if (!IthIsWine()) {
    // jichi 9/22/2013: For ChuSingura46+1 on Windows 7
    //   t = L"C:\\Windows\\system32";
    //   obj = L"\\Sessions\\1\\BaseNamedObjects";
    // On Windows XP
    //   t = L"C:\\WINDOWS\\system32";
    //   obj = L"\\BaseNamedObjects";
    MEMORY_BASIC_INFORMATION info;
    if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), peb->ReadOnlySharedMemoryBase, MemoryBasicInformation, &info, sizeof(info), &size)))
      return FALSE;
    DWORD base = (DWORD)peb->ReadOnlySharedMemoryBase;
    DWORD end = base + info.RegionSize - 0x40;
    static WCHAR system32[] = L"system32";
    for (;base < end; base += 2)
      if (::memcmp((PVOID)base, system32, 0x10) == 0) {
        t = (LPWSTR)base;
        while (*t-- != L':');
        obj = (LPWSTR)base;
        while (*obj != L'\\') obj++;
        break;
      }
    if (base == end)
      return FALSE;
  }
  //ITH_MSG(t);
  //ITH_MSG(obj);

  LDR_DATA_TABLE_ENTRY *ldr_entry = (LDR_DATA_TABLE_ENTRY*)peb->Ldr->InLoadOrderModuleList.Flink;
  wcscpy(file_path + 4, ldr_entry->FullDllName.Buffer);
  current_dir = wcsrchr(file_path,L'\\') + 1;
  *current_dir = 0;
  RtlInitUnicodeString(&us, file_path);
  if (!NT_SUCCESS(NtOpenFile(&dir_obj,FILE_LIST_DIRECTORY|FILE_TRAVERSE|SYNCHRONIZE,
      &oa,&ios,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT)))
    return FALSE;

  // jichi 9/22/2013: Get kernel object session ID
  // See: http://www.brianbondy.com/blog/id/100/
  // It seems that on sessionId is 0 on Windows XP, and 1 on Windows Vista and later
  // I assume that sessionId is in [0,9]
  // For ChuSingura46+1 on Windows 7
  //    obj = L"\\Sessions\\1\\BaseNamedObjects";
  // On Windows XP
  //    obj = L"\\BaseNamedObjects";
  //ITH_MSG(obj);
  {
    if (obj)
      RtlInitUnicodeString(&us, obj);
    else { // jichi ITH is on Wine
      // Get session ID in PEB
      // See: http://msdn.microsoft.com/en-us/library/bb432286%28v=vs.85%29.aspx
      DWORD sessionId = peb->SessionId;
      if (!sessionId) // Windows XP
        RtlInitUnicodeString(&us, L"\\BaseNamedObjects");
      else { // Windows Vista +
        wchar_t path[] = L"\\Sessions\\0\\BaseNamedObjects";
        path[10] += (wchar_t)sessionId; // replace 0 with the session ID
        RtlInitUnicodeString(&us, path);
      }
    }
  }

  if (!NT_SUCCESS(NtOpenDirectoryObject(&::root_obj, READ_CONTROL|0xF, &oa)))
    return FALSE;

  ::page = peb->InitAnsiCodePageData;

  // jichi 9/23/2013: Access violation on Wine
  if (IthIsWine())
    // One wine, there is no C_932.nls
    //page_locale = 0x4e4; // 1252, English
    //page_locale = GetACP(); // This will return 932 when LC_ALL=ja_JP.UTF-8 on wine
    // Always set locale to CP932 on Wine, since C_932.nls could be missing.
    ::page_locale = 0x3a4; // = 932
  else
    ::page_locale = *(DWORD *)page >> 16;

  if (::page_locale == 0x3a4) {
    oa.hRootDirectory = ::root_obj;
    oa.uAttributes |= OBJ_OPENIF;
  } else { // Unreachable or wine
//#ifdef ITH_WINE
//    // jichi 9/22/2013: For ChuSingura46+1 on Windows 7
//    //t = L"C:\\Windows\\system32";
//    wchar_t buffer[MAX_PATH];
//    if (!t) { // jichi 9/22/2013: ITH is one wine
//      if (UINT sz = ::GetSystemDirectoryW(buffer, MAX_PATH)) {
//        buffer[sz] = 0;
//        t = buffer;
//      } else
//        t = L"C:\\Windows\\System32"; // jichi 9/29/2013: sth is wrong here
//    }
//#endif // ITH_WINE

    ::wcscpy(file_path + 4, t);
    t = file_path;
    while(*++t);
    if (*(t-1)!=L'\\')
      *t++=L'\\';
    ::wcscpy(t,L"C_932.nls");
    RtlInitUnicodeString(&us, file_path);
    if (!NT_SUCCESS(NtOpenFile(&codepage_file, FILE_READ_DATA, &oa, &ios,FILE_SHARE_READ,0)))
      return FALSE;
    oa.hRootDirectory = ::root_obj;
    oa.uAttributes |= OBJ_OPENIF;
    RtlInitUnicodeString(&us, L"JPN_CodePage");
    if (!NT_SUCCESS(NtCreateSection(&codepage_section, SECTION_MAP_READ,
        &oa,0, PAGE_READONLY, SEC_COMMIT, codepage_file)))
      return FALSE;
    NtClose(codepage_file);
    size = 0;
    ::page = nullptr;
    if (!NT_SUCCESS(NtMapViewOfSection(::codepage_section, NtCurrentProcess(),
        &::page,
        0, 0, 0, &size, ViewUnmap, 0,
        PAGE_READONLY)))
      return FALSE;
  }
  if (ITH_ENABLE_THREADMAN) {
    RtlInitUnicodeString(&us, ITH_THREADMAN_SECTION);
    if (!NT_SUCCESS(NtCreateSection(&thread_man_section, SECTION_ALL_ACCESS, &oa, &sec_size,
        PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0)))
      return FALSE;
    size = 0;
    // http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Section/NtMapViewOfSection.html
    thread_man_ = nullptr;
    if (!NT_SUCCESS(NtMapViewOfSection(thread_man_section, NtCurrentProcess(),
       (LPVOID *)&thread_man_,
       0,0,0, &size, ViewUnmap, 0,
       PAGE_EXECUTE_READWRITE)))
      return FALSE;
  }
  return TRUE;
}

//Release resources allocated by IthInitSystemService.
//After destroying the heap, all memory allocated by ITH module is returned to system.
void IthCloseSystemService()
{
  if (::page_locale != 0x3a4) {
    NtUnmapViewOfSection(NtCurrentProcess(), ::page);
    NtClose(::codepage_section);
  }
  if (ITH_ENABLE_THREADMAN) {
    NtUnmapViewOfSection(NtCurrentProcess(), ::thread_man_);
    NtClose(::thread_man_section);
  }
  NtClose(::root_obj);
#ifdef ITH_HAS_HEAP
  RtlDestroyHeap(::hHeap);
#endif // ITH_HAS_HEAP
}

//Check for existence of a file in current folder. Thread safe after init.
//For ITH main module, it's ITH folder. For target process it's the target process's current folder.
BOOL IthCheckFile(LPCWSTR file)
{
  //return PathFileExistsW(file);   // jichi: need Shlwapi.lib

  //return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
  //return GetFileAttributesW(file) != INVALID_FILE_ATTRIBUTES; // jichi: does not consider the current app's path

  // jichi 9/22/2013: Following code does not work in Wine
  // See: http://stackoverflow.com/questions/3828835/how-can-we-check-if-a-file-exists-or-not-using-win32-program
   //WIN32_FIND_DATA FindFileData;
   //HANDLE handle = FindFirstFileW(file, &FindFileData);
   //if (handle != INVALID_HANDLE_VALUE) {
   //  FindClose(handle);
   //  return TRUE;
   //}
   //return FALSE;
  if (IthIsWine()) {
    HANDLE hFile = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, 0);
    if (hFile != INVALID_HANDLE_VALUE) {
      CloseHandle(hFile);
      return TRUE;
    } else if (!wcschr(file, L':')) { // jichi: this is relative path
      // jichi 9/22/2013: Change current directory to the same as main module path
      // Otherwise NtFile* would not work for files with relative paths.
      if (const wchar_t *path = GetMainModulePath()) // path to VNR's python exe
        if (const wchar_t *base = wcsrchr(path, L'\\')) {
          size_t dirlen = base - path + 1;
          if (dirlen + wcslen(file) < MAX_PATH) {
            wchar_t buf[MAX_PATH];
            wcsncpy(buf, path, dirlen);
            wcscpy(buf + dirlen, file);
            return IthCheckFile(buf);
          }
        }
    }
  } else { // not wine
    HANDLE hFile;
    IO_STATUS_BLOCK isb;
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, file);
    OBJECT_ATTRIBUTES oa = { sizeof(oa), dir_obj, &us, 0, 0, 0};
    // jichi 9/22/2013: Following code does not work in Wine
    if (NT_SUCCESS(NtCreateFile(&hFile, FILE_READ_DATA, &oa, &isb, 0, 0, FILE_SHARE_READ, FILE_OPEN, 0, 0, 0))) {
      NtClose(hFile);
      return TRUE;
    }
  }
  return FALSE;
  //return IthGetFileInfo(file,file_info);
  //wcscpy(current_dir,file);
}

//Check for existence of files in current folder.
//Unlike IthCheckFile, this function allows wildcard character.
BOOL IthFindFile(LPCWSTR file)
{
  NTSTATUS status;
  HANDLE h;
  UNICODE_STRING us;
  OBJECT_ATTRIBUTES oa = {sizeof(oa), dir_obj, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  us.Buffer = const_cast<LPWSTR>(file);
  LPCWSTR path = wcsrchr(file, L'\\');
  if (path) {
    us.Length = (path - file) << 1;
    us.MaximumLength = us.Length;
  } else {
    us.Length = 0;
    us.MaximumLength = 0;
  }
  IO_STATUS_BLOCK ios;
  if (NT_SUCCESS(NtOpenFile(&h,FILE_LIST_DIRECTORY|SYNCHRONIZE,
      &oa,&ios,FILE_SHARE_READ,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT))) {
    BYTE info[0x400];
    if (path)
      RtlInitUnicodeString(&us, path + 1);
    else
      RtlInitUnicodeString(&us, file);
    status = NtQueryDirectoryFile(h,0,0,0,&ios,info,0x400,FileBothDirectoryInformation,TRUE,&us,TRUE);
    NtClose(h);
    return NT_SUCCESS(status);
  }
  return FALSE;
}
//Analogous to IthFindFile, but return detail information in 'info'.
BOOL IthGetFileInfo(LPCWSTR file, LPVOID info, DWORD size)
{
  NTSTATUS status;
  HANDLE h;
  UNICODE_STRING us;
  LPCWSTR path = wcsrchr(file, L'\\');
  us.Buffer = const_cast<LPWSTR>(file);
  if (path) {
    us.Length = (path - file) << 1;
    us.MaximumLength = us.Length;
  } else {
    us.Length = 0;
    us.MaximumLength = 0;
  }
  //RtlInitUnicodeString(&us,file);
  OBJECT_ATTRIBUTES oa = {sizeof(oa), dir_obj, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  IO_STATUS_BLOCK ios;
  if (NT_SUCCESS(NtOpenFile(&h,FILE_LIST_DIRECTORY|SYNCHRONIZE,
      &oa,&ios,FILE_SHARE_READ,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT))) {
    RtlInitUnicodeString(&us,file);
    status = NtQueryDirectoryFile(h,0,0,0,&ios,info,size,FileBothDirectoryInformation,0,&us,0);
    status = NT_SUCCESS(status);
    NtClose(h);
  } else
    status = FALSE;
  return status;
}

//Check for existence of a file with full NT path(start with \??\).
BOOL IthCheckFileFullPath(LPCWSTR file)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us, file);
  OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  if (NT_SUCCESS(NtCreateFile(&hFile,FILE_READ_DATA,&oa,&isb,0,0,FILE_SHARE_READ,FILE_OPEN,0,0,0))) {
    NtClose(hFile);
    return TRUE;
  } else
    return FALSE;
}
//Create or open file in current folder. Analogous to Win32 CreateFile.
//option: GENERIC_READ / GENERIC_WRITE.
//share: FILE_SHARE_READ / FILE_SHARE_WRITE / FILE_SHARE_DELETE. 0 for exclusive access.
//disposition: FILE_OPEN / FILE_OPEN_IF.
//Use FILE_OPEN instead of OPEN_EXISTING and FILE_OPEN_IF for CREATE_ALWAYS.
HANDLE IthCreateFile(LPCWSTR name, DWORD option, DWORD share, DWORD disposition)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us, name);
  OBJECT_ATTRIBUTES oa = { sizeof(oa), dir_obj, &us, OBJ_CASE_INSENSITIVE, 0, 0 };
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  return NT_SUCCESS(NtCreateFile(&hFile,
      option|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
      &oa,&isb,0,0,share,disposition,
      FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)) ?
    hFile : INVALID_HANDLE_VALUE;
}
//Create a directory file in current folder.
HANDLE IthCreateDirectory(LPCWSTR name)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us,name);
  OBJECT_ATTRIBUTES oa = {sizeof(oa), dir_obj, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  return NT_SUCCESS(NtCreateFile(&hFile,FILE_LIST_DIRECTORY|FILE_TRAVERSE|SYNCHRONIZE,&oa,&isb,0,0,
      FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_OPEN_IF,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,0,0)) ?
     hFile : INVALID_HANDLE_VALUE;
}

HANDLE IthCreateFileInDirectory(LPCWSTR name, HANDLE dir, DWORD option, DWORD share, DWORD disposition)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us,name);
  if (dir == 0) dir = dir_obj;
  OBJECT_ATTRIBUTES oa = {sizeof(oa), dir, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  return NT_SUCCESS(NtCreateFile(&hFile,
      option|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
      &oa,&isb,0,0,share,disposition,
      FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)) ?
    hFile : INVALID_HANDLE_VALUE;
}

//Analogous to IthCreateFile, but with full NT path.
HANDLE IthCreateFileFullPath(LPCWSTR path, DWORD option, DWORD share, DWORD disposition)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us,path);
  OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, &us, OBJ_CASE_INSENSITIVE, 0, 0};
  HANDLE hFile;
  IO_STATUS_BLOCK isb;
  return NT_SUCCESS(NtCreateFile(&hFile,
      option|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
      &oa,&isb,0,0,share,disposition,
      FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)) ?
    hFile : INVALID_HANDLE_VALUE;
}

//Create section object for sharing memory between processes.
//Similar to CreateFileMapping.
HANDLE IthCreateSection(LPCWSTR name, DWORD size, DWORD right)
{
// jichi 9/25/2013: GENERIC_ALL does NOT work one wine
// See ZwCreateSection: http://msdn.microsoft.com/en-us/library/windows/hardware/ff566428%28v=vs.85%29.aspx
//#ifdef ITH_WINE
  enum { DesiredAccess = SECTION_ALL_ACCESS };
//#else
//  enum { DesiredAccess = GENERIC_ALL }; // jichi 9/25/2013: not sure whhy ITH is usin GENERIC_ALL
//#endif // ITH_WINE
#define eval    (NT_SUCCESS(NtCreateSection(&hSection, DesiredAccess, poa, &s, \
      right, SEC_COMMIT, 0)) ? hSection : INVALID_HANDLE_VALUE)
  HANDLE hSection;
  LARGE_INTEGER s = {size, 0};
  OBJECT_ATTRIBUTES *poa = nullptr;
  // jichi 9/25/2013: What the fxxx?! poa in the orignal source code of ITH
  // is pointed to freed object on the stack?! This will crash wine!
  if (name) {
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, name);
    OBJECT_ATTRIBUTES oa = {sizeof(oa), root_obj, &us,OBJ_OPENIF,0,0};
    poa = &oa;
    return eval;
  } else
    return eval;
#undef retval
}

//Create event object. Similar to CreateEvent.
HANDLE IthCreateEvent(LPCWSTR name, DWORD auto_reset, DWORD init_state)
{
#define eval  (NT_SUCCESS(NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, poa, auto_reset, init_state)) ? \
     hEvent : INVALID_HANDLE_VALUE)
  HANDLE hEvent;
  OBJECT_ATTRIBUTES *poa = nullptr;
  // jichi 9/25/2013: What the fxxx?! poa in the orignal source code of ITH
  // is pointed to freed object on the stack?! This will crash wine!
  if (name) {
    UNICODE_STRING us;
    RtlInitUnicodeString(&us,name);
    OBJECT_ATTRIBUTES oa = {sizeof(oa), root_obj, &us, OBJ_OPENIF, 0, 0};
    poa = &oa;
    return eval;
  } else
    return eval;
#undef eval
}

HANDLE IthOpenEvent(LPCWSTR name)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us, name);
  OBJECT_ATTRIBUTES oa = { sizeof(oa), root_obj, &us, 0, 0, 0 };
  HANDLE hEvent;
  return NT_SUCCESS(NtOpenEvent(&hEvent, EVENT_ALL_ACCESS, &oa)) ?
     hEvent : INVALID_HANDLE_VALUE;
}

void IthSetEvent(HANDLE hEvent) { NtSetEvent(hEvent, 0); }

void IthResetEvent(HANDLE hEvent) { NtClearEvent(hEvent); }

//Create mutex object. Similar to CreateMutex.
//If 'exist' is not null, it will be written 1 if mutex exist.
HANDLE IthCreateMutex(LPCWSTR name, BOOL InitialOwner, DWORD *exist)
{
#define eval    NtCreateMutant(&hMutex, MUTEX_ALL_ACCESS, poa, InitialOwner)
  UNICODE_STRING us;
  HANDLE hMutex;
  NTSTATUS status;
  OBJECT_ATTRIBUTES *poa = nullptr;
  // jichi 9/25/2013: What the fxxx?! poa in the orignal source code of ITH
  // is pointed to freed object on the stack?! This will crash wine!
  if (name) {
    RtlInitUnicodeString(&us, name);
    OBJECT_ATTRIBUTES oa = {sizeof(oa), root_obj, &us, OBJ_OPENIF, 0, 0};
    poa = &oa;
    status = eval;
  } else
    status = eval;
  if (NT_SUCCESS(status)) {
    if (exist)
      *exist = status == STATUS_OBJECT_NAME_EXISTS;
    return hMutex;
  } else
    return INVALID_HANDLE_VALUE;
#undef eval
}

HANDLE IthOpenMutex(LPCWSTR name)
{
  UNICODE_STRING us;
  RtlInitUnicodeString(&us, name);
  OBJECT_ATTRIBUTES oa = {sizeof(oa), root_obj, &us, 0, 0, 0};
  HANDLE hMutex;
  if (NT_SUCCESS(NtOpenMutant(&hMutex, MUTEX_ALL_ACCESS, &oa)))
    return hMutex;
  else
    return INVALID_HANDLE_VALUE;
}

BOOL IthReleaseMutex(HANDLE hMutex)
{ return NT_SUCCESS(NtReleaseMutant(hMutex, 0)); }

//Create new thread. 'hProc' must have following right.
//PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE.
HANDLE IthCreateThread(LPCVOID start_addr, DWORD param, HANDLE hProc)
{
  HANDLE hThread;
  // jichi 9/27/2013: NtCreateThread is not implemented in Wine 1.7
  if (thread_man_) { // Windows XP
    // jichi 9/29/2013: Reserved && commit stack size
    // See: http://msdn.microsoft.com/en-us/library/windows/desktop/aa366803%28v=vs.85%29.aspx
    // See: http://msdn.microsoft.com/en-us/library/ms810627.aspx
    enum { DEFAULT_STACK_LIMIT = 0x400000 };
    enum { DEFAULT_STACK_COMMIT = 0x10000 };
    enum { PAGE_SIZE = 0x1000 };
    CLIENT_ID id;
    LPVOID protect;
    USER_STACK stack = {};
    CONTEXT ctx = {CONTEXT_FULL};
    DWORD size = DEFAULT_STACK_LIMIT,
          commit = DEFAULT_STACK_COMMIT;
    if (!NT_SUCCESS(NtAllocateVirtualMemory(hProc, &stack.ExpandableStackBottom, 0, &size, MEM_RESERVE, PAGE_READWRITE)))
      return INVALID_HANDLE_VALUE;

    stack.ExpandableStackBase = (char *)stack.ExpandableStackBottom + size;
    stack.ExpandableStackLimit = (char *)stack.ExpandableStackBase - commit;
    size = PAGE_SIZE;
    commit += size;
    protect = (char *)stack.ExpandableStackBase - commit;
    NtAllocateVirtualMemory(hProc, &protect, 0, &commit, MEM_COMMIT, PAGE_READWRITE);
    DWORD oldAccess; // jichi 9/29/2013: unused
    NtProtectVirtualMemory(hProc, &protect, &size, PAGE_READWRITE|PAGE_GUARD, &oldAccess);
    ctx.SegGs = 0;
    ctx.SegFs = 0x38;
    ctx.SegEs = 0x20;
    ctx.SegDs = 0x20;
    ctx.SegSs = 0x20;
    ctx.SegCs = 0x18;
    ctx.EFlags = 0x3000;
    ctx.Eip = (DWORD)thread_man_->GetProcAddr(hProc);
    ctx.Eax = (DWORD)start_addr;
    ctx.Ecx = ctx.Eip + 0x40;
    ctx.Edx = 0xffffffff;
    ctx.Esp = (DWORD)stack.ExpandableStackBase - 0x10;
    ctx.Ebp = param;

     // NTSYSAPI
     // NTSTATUS
     // NTAPI
     // NtCreateThread(
     //   _Out_ PHANDLE             ThreadHandle,
     //   _In_  ACCESS_MASK         DesiredAccess,
     //   _In_  POBJECT_ATTRIBUTES  ObjectAttributes,
     //   _In_  HANDLE              ProcessHandle,
     //   _Out_ PCLIENT_ID          ClientId,
     //   _In_  PCONTEXT            ThreadContext,
     //   _In_  PUSER_STACK         UserStack,
     //   _In_  BOOLEAN             CreateSuspended
     // );
    if (NT_SUCCESS(NtCreateThread(
        &hThread, // _Out_ PHANDLE             ThreadHandle,
        THREAD_ALL_ACCESS, // _In_ ACCESS_MASK DesiredAccess,
        nullptr,  // _In_  POBJECT_ATTRIBUTES  ObjectAttributes,
        hProc,    // _In_  HANDLE              ProcessHandle,
        &id,      // _Out_ PCLIENT_ID          ClientId,
        &ctx,     // _In_  PCONTEXT            ThreadContext,
        &stack,   // _In_  PUSER_STACK         UserStack,
        TRUE      // _In_  BOOLEAN             CreateSuspended
      ))) {
      // On x64 Windows, NtCreateThread in ntdll calls NtCreateThread in ntoskrnl via WOW64,
      // which maps 32-bit system call to the correspond 64-bit version.
      // This layer doesn't correctly copy whole CONTEXT structure, so we must set it manually
      // after the thread is created.
      // On x86 Windows, this step is not necessary.
      NtSetContextThread(hThread, &ctx);
      NtResumeThread(hThread, 0);
    } else
      hThread = INVALID_HANDLE_VALUE;

  } else {
    // jichi 9/27/2013: CreateRemoteThread works on both Wine and Windows 7
    // Use CreateRemoteThread instead
    // FIXME 10/5/2031: Though sometimes works, CreateRemoteThread randomly crashes on wine.
    // See:
    // - http://www.unknowncheats.me/forum/c-and-c/64775-createremotethread-dll-injection.html
    // - http://source.winehq.org/WineAPI/CreateRemoteThread.html
    // - http://msdn.microsoft.com/en-us/library/windows/desktop/ms682437%28v=vs.85%29.aspx
    // HANDLE WINAPI CreateRemoteThread(
    //   _In_   HANDLE hProcess,
    //   _In_   LPSECURITY_ATTRIBUTES lpThreadAttributes,
    //   _In_   SIZE_T dwStackSize,
    //   _In_   LPTHREAD_START_ROUTINE lpStartAddress,
    //   _In_   LPVOID lpParameter,
    //   _In_   DWORD dwCreationFlags,
    //   _Out_  LPDWORD lpThreadId
    // );
    //ITH_TRY {
    if (hProc == INVALID_HANDLE_VALUE)
      hProc = GetCurrentProcess();
    //DWORD dwThreadId;
    hThread = CreateRemoteThread(
      hProc,        // _In_ HANDLE hProcess,
      nullptr,      // _In_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
      0,            // _In_ SIZE_T dwStackSize,
      (LPTHREAD_START_ROUTINE)start_addr,  // _In_ LPTHREAD_START_ROUTINE lpStartAddress,
      (LPVOID)param,  // _In_ LPVOID lpParameter,
      0,            //STACK_SIZE_PARAM_IS_A_RESERVATION  // _In_ DWORD dwCreationFlags,
      nullptr       // _Out_ LPDWORD lpThreadId
    );
    if (!hThread)   // jichi: this function returns nullptr instead of -1
      hThread = INVALID_HANDLE_VALUE;
    //} ITH_EXCEPT {
    //  ITH_WARN(L"exception");
    //  hThread = INVALID_HANDLE_VALUE;
    //}
  }
  /*
  else {
    // jichi 9/29/2013: Also work on Wine and Windows 7
    // See: http://waleedassar.blogspot.com/2012/06/createremotethread-vs.html
    CLIENT_ID id;
    //DWORD size = DEFAULT_STACK_LIMIT,
    //      commit = DEFAULT_STACK_COMMIT;
    DWORD reserve = 0,
          commit = 0;
    // http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
    //   NTSYSAPI
    //   NTSTATUS
    //   NTAPI
    //   RtlCreateUserThread(
    //     IN HANDLE ProcessHandle,
    //     IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    //     IN BOOLEAN CreateSuspended,
    //     IN ULONG StackZeroBits,
    //     IN OUT PULONG StackReserved,
    //     IN OUT PULONG StackCommit,
    //     IN PVOID StartAddress,
    //     IN PVOID StartParameter OPTIONAL,
    //     OUT PHANDLE ThreadHandle,
    //     OUT PCLIENT_ID ClientID);
    if (!NT_SUCCESS(RtlCreateUserThread(
        hProc,        // HANDLE hProcess,
        nullptr,      // IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
        FALSE,        // IN BOOLEAN CreateSuspended,
        0,            // IN ULONG StackZeroBits,
        &reserve,     // IN OUT PULONG StackReserved,
        &commit,      // IN OUT PULONG StackCommit,
        (LPVOID)start_addr, // IN PVOID StartAddress,
        (LPVOID)param,// IN PVOID StartParameter OPTIONAL,
        &hThread,     // OUT PHANDLE ThreadHandle,
        &id           // OUT PCLIENT_ID ClientID
      )))
      hThread = INVALID_HANDLE_VALUE;
  }
  */
  return hThread;
}

//Query module export table. Return function address if found.
//Similar to GetProcAddress
DWORD GetExportAddress(DWORD hModule,DWORD hash)
{
  IMAGE_DOS_HEADER *DosHdr;
  IMAGE_NT_HEADERS *NtHdr;
  IMAGE_EXPORT_DIRECTORY *ExtDir;
  UINT uj;
  char* pcExportAddr,*pcFuncPtr,*pcBuffer;
  DWORD dwReadAddr,dwFuncAddr,dwFuncName;
  WORD wOrd;
  DosHdr = (IMAGE_DOS_HEADER*)hModule;
  if (IMAGE_DOS_SIGNATURE==DosHdr->e_magic) {
    dwReadAddr=hModule+DosHdr->e_lfanew;
    NtHdr=(IMAGE_NT_HEADERS*)dwReadAddr;
    if (IMAGE_NT_SIGNATURE == NtHdr->Signature) {
      pcExportAddr = (char*)((DWORD)hModule+
          (DWORD)NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
      if (!pcExportAddr)
        return 0;
      ExtDir = (IMAGE_EXPORT_DIRECTORY*)pcExportAddr;
      pcExportAddr = (char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfNames);

      for (uj = 0; uj < ExtDir->NumberOfNames; uj++) {
        dwFuncName = *(DWORD *)pcExportAddr;
        pcBuffer = (char*)((DWORD)hModule+dwFuncName);
        if (GetHash(pcBuffer) == hash) {
          pcFuncPtr = (char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfNameOrdinals+(uj*sizeof(WORD)));
          wOrd = *(WORD*)pcFuncPtr;
          pcFuncPtr = (char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfFunctions+(wOrd*sizeof(DWORD)));
          dwFuncAddr = *(DWORD *)pcFuncPtr;
          return hModule+dwFuncAddr;
        }
        pcExportAddr += sizeof(DWORD);
      }
    }
  }
  return 0;
}

} // extern "C"

// EOF

/*__declspec(naked) void normal_asm()
{
  __asm
  {
    push ecx
    push edx
    mov fs:[0],esp
    push ebp
    call eax
_terminate:
    push eax
    push -2
    call dword ptr [NtTerminateThread]
  }
}*/

/*
__declspec(naked) void RegToStrAsm()
{
  __asm
  {
    mov edx, 8
_cvt_loop:
    mov eax, ecx
    and eax, 0xF
    cmp eax, 0xA
    jb _below_ten
    add al,7
_below_ten:
    add al,0x30
    stosw
    ror ecx,4
    dec edx
    jne _cvt_loop
    retn
  }
}
__declspec(naked) void except_asm()
{
  __asm
  {
    mov eax,[esp + 4]
    xor esi,esi
    mov ebp,[eax]
    mov ecx,[esp + 0xC]
    mov ebx,[ecx + 0xB8]
    sub esp,0x240
    lea edi,[esp + 0x40]
    mov eax,esp
    push esi
    push 0x1C
    push eax
    push esi
    push ebx
    push -1
    call dword ptr [NtQueryVirtualMemory]
    test eax,eax
    jne _terminate
    mov eax,esp
    push eax
    push 0x200
    push edi
    push 2
    push ebx
    push -1
    call dword ptr [NtQueryVirtualMemory]
    test eax,eax
    jne _terminate
    pop esi
    xadd edi,esi
    std
    mov al,0x5C
    repen scasw
    mov word ptr [edi + 2], 0x3A
    mov ecx,ebx
    sub ecx,[esp]
    call RegToStrAsm
    inc edi
    inc edi
    xchg esi,edi
    mov ecx,ebp
    call RegToStrAsm
    inc edi
    inc edi
    xor eax,eax
    mov [edi + 0x10], eax
    push 0
    push edi
    push esi
    push 0
    call dword ptr [MessageBoxW]
    or eax, -1
    jmp _terminate
  }
}

//Prompt for file name.
HANDLE IthPromptCreateFile(DWORD option, DWORD share, DWORD disposition)
{
  OPENFILENAME ofn = {sizeof(ofn)};       // common dialog box structure
  WCHAR szFile[MAX_PATH];       // buffer for file name
  wcscpy(current_dir,L"ITH_export.txt");
  wcscpy(szFile,file_path);

  //szFile[0]=0;
  ofn.lpstrFile = szFile + 4;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrFilter = L"Text\0*.txt";
  BOOL result;
  if (disposition==FILE_OPEN)
    result=GetOpenFileName(&ofn);
  else
    result=GetSaveFileName(&ofn);
  if (result)
  {
    LPWSTR s=szFile+wcslen(szFile) - 4;
    if (_wcsicmp(s,L".txt")!=0) wcscpy(s + 4,L".txt");
    return IthCreateFileFullPath(szFile,option,share,disposition);
  }
  else return INVALID_HANDLE_VALUE;
}
*/

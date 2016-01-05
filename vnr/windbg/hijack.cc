// hijack.cc
// 1/27/2013 jichi
#include "windbg/hijack.h"
#include "windbg/windbg_p.h"

#ifdef _MSC_VER
# pragma warning (disable:4996)   // C4996: use POSIX function (stricmp)
#endif // _MSC_VER

//#define DEBUG "winsec"
#include "sakurakit/skdebug.h"

WINDBG_BEGIN_NAMESPACE

// - Inline Hook -
// See: http://asdf.wkeya.com/code/apihook6.html
PVOID overrideFunctionA(HMODULE stealFrom, LPCSTR oldFunctionModule, LPCSTR functionName, LPCVOID newFunction)
{
  if (!stealFrom)
    return nullptr;
  //HMODULE oldModule = GetModuleHandleA(oldFunctionModule);
  //if (!oldModule)
  //  return nullptr;
  //void *originalAddress = GetProcAddress(oldModule, functionName);
  LPVOID originalAddress = details::getModuleFunctionAddressA(functionName, oldFunctionModule);
  if (!originalAddress)
    return nullptr;
  IMAGE_DOS_HEADER *dosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(stealFrom);
  char *base = reinterpret_cast<char *>(stealFrom);
  if (::IsBadReadPtr(dosHeader, sizeof(IMAGE_DOS_HEADER)) || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return nullptr;
  IMAGE_NT_HEADERS *ntHeader =
      reinterpret_cast<IMAGE_NT_HEADERS* >(base + dosHeader->e_lfanew);
  if (::IsBadReadPtr(ntHeader, sizeof(IMAGE_NT_HEADERS)) || ntHeader->Signature != IMAGE_NT_SIGNATURE)
    return nullptr;
  if (!ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
    return nullptr;
  // See: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
  IMAGE_IMPORT_DESCRIPTOR *import =
      reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(base + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

  // scan memory
  // TODO: add a maximum loop counter here!
  while (import->Name) {
    char *name = base + import->Name;
    if (!::stricmp(name, oldFunctionModule))
      break;
    import++;
  }
  if (!import->Name)
    return nullptr;
  IMAGE_THUNK_DATA *thunk = reinterpret_cast<IMAGE_THUNK_DATA *>(base + import->FirstThunk);
  while (thunk->u1.Function) {
    if ((ULONG_PTR)thunk->u1.Function == (ULONG_PTR)originalAddress) {
      ULONG_PTR *addr = reinterpret_cast<ULONG_PTR *>(&thunk->u1.Function);

      // See: http://asdf.wkeya.com/code/apihook6.html
      // Inline hook mechanism:
      //
      // LPVOID InlineHook3( PUINT8 mem, DWORD dwLen, PUINT8 pfOld, PUINT8 pfNew )
      // {
      //   DWORD dwOldProtect;
      //   VirtualProtect( ( PUINT8 )( pfOld ), dwLen, PAGE_READWRITE, &dwOldProtect );
      //   // 関数のエントリーから指定したbyte数をメモリの前方にコピー
      //   // メモリの数byte後方からオリジナルへのジャンプを作成
      //   // 指定の関数アドレスから5byteをフックへのjmp命令に書き換え
      //   VirtualProtect( ( PUINT8 )( pfOld ), dwLen, dwOldProtect, &dwOldProtect );
      //   return ( PVOID )mem;
      // }

      MEMORY_BASIC_INFORMATION mbi;
      if (::VirtualQuery((LPVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        DWORD dwOldProtect;
        if (::VirtualProtect(mbi.BaseAddress, ((ULONG_PTR)addr + 8)-(ULONG_PTR)mbi.BaseAddress, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
          *addr = (ULONG_PTR)newFunction;
          ::VirtualProtect(mbi.BaseAddress, ((ULONG_PTR)addr + 8)-(ULONG_PTR)mbi.BaseAddress, dwOldProtect, &dwOldProtect);
          return originalAddress;
        }
      }

    }
    thunk++;
  }
  return nullptr;
}

WINDBG_END_NAMESPACE

// EOF

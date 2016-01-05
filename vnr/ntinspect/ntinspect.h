#pragma once

// ntinspect.h
// 4/20/2014 jichi

#include <windows.h>
#ifndef MEMDBG_NO_STL
# include <functional>
#endif // MEMDBG_NO_STL

#ifndef NTINSPECT_BEGIN_NAMESPACE
# define NTINSPECT_BEGIN_NAMESPACE  namespace NtInspect {
#endif
#ifndef NTINSPECT_END_NAMESPACE
# define NTINSPECT_END_NAMESPACE    } // NtInspect
#endif

NTINSPECT_BEGIN_NAMESPACE

// Get the module handle of the current module (not the current process that is GetModuleHandleA(0))
HMODULE getCurrentModuleHandle();

///  Get current module name in fs:0x30
BOOL getProcessName(_Out_ LPWSTR buffer, _In_ int bufferSize);

/**
 *  Get the memory range of the module if succeed
 *  @param  moduleName
 *  @param[out[  lowerBound
 *  @param[out]  upperBound
 *  @return  if succeed
 */
BOOL getModuleMemoryRange(_In_ LPCWSTR moduleName, _Out_ DWORD *lowerBound, _Out_ DWORD *upperBound);

///  Get memory of the current process module
BOOL getProcessMemoryRange(_Out_ DWORD *lowerBound, _Out_ DWORD *upperBound);

#ifndef NTINSPECT_NO_STL
///  Iterate module information and return false if abort iteration.
typedef std::function<bool (HMODULE hModule, LPCWSTR moduleName)> iter_module_fun_t;
#else
typedef bool (* iter_module_fun_t)(HMODULE hModule, LPCWSTR moduleName);
#endif // NTINSPECT_NO_STL

/**
 *  Iterate all modules
 *  @param  fun  the first parameter is the address of the caller, and the second parameter is the address of the call itself
 *  @return  false if return early, and true if iterate all elements
 */
bool iterModule(const iter_module_fun_t &fun);

/**
 *  Return the absolute address of the function imported from the given module
 *  @param  functionName
 *  @param* hModule  find from any module when null
 *  @return  function address or 0
 */
DWORD getModuleExportFunction(HMODULE hModule, LPCSTR functionName);

inline DWORD getModuleExportFunctionA(LPCSTR moduleName, LPCSTR functionName)
{ return getModuleExportFunction(::GetModuleHandleA(moduleName), functionName); }

inline DWORD getModuleExportFunctionW(LPCWSTR moduleName, LPCSTR functionName)
{ return getModuleExportFunction(::GetModuleHandleW(moduleName), functionName); }

///  Get the function address exported from any module
DWORD getExportFunction(LPCSTR functionName);

/**
 *  Get the import address in the specified module
 *  @param  hModule
 *  @param  exportAddress  absolute address of the function exported from other modules
 *  @return  function address or 0
 */
DWORD getModuleImportAddress(HMODULE hModule, DWORD exportAddress);

inline DWORD getModuleImportAddressA(LPCSTR moduleName, DWORD exportAddress)
{ return getModuleImportAddress(::GetModuleHandleA(moduleName), exportAddress); }

inline DWORD getModuleImportAddressW(LPCWSTR moduleName, DWORD exportAddress)
{ return getModuleImportAddress(::GetModuleHandleW(moduleName), exportAddress); }

///  Get the import address in the current executable
inline DWORD getProcessImportAddress(DWORD exportAddress)
{ return getModuleImportAddress(::GetModuleHandleA(nullptr), exportAddress); }


NTINSPECT_END_NAMESPACE

// EOF

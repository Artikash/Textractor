/*  Copyright (C) 2010-2012  kaosu (qiupf2000@gmail.com)
 *  This file is part of the Interactive Text Hooker.

 *  Interactive Text Hooker is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "utility.h"
#include "ith/host/srv.h"
#include "ith/host/hookman.h"
#include "ith/common/types.h"
#include "ith/common/const.h"

extern HookManager* man; // main.cpp

std::wstring GetDriveLetter(const std::wstring& devicePath);
std::wstring GetWindowsPath(const std::wstring& fileObjectPath);
PVOID GetAllocationBase(DWORD pid, LPCVOID);
std::wstring GetModuleFileNameAsString(DWORD pid, PVOID allocationBase);
std::wstring GetModuleFileNameAsString();
std::wstring GetProcessPath(HANDLE hProc);

void ConsoleOutput(LPCWSTR text)
{
	man->AddConsoleOutput(text);
}

void ConsoleOutput(LPCSTR text)
{
	int wc_length = MB_WC_count(text, -1);
	LPWSTR wc = new WCHAR[wc_length];
	MB_WC(text, wc, wc_length);
	man->AddConsoleOutput(wc);
	delete wc;
}

std::wstring GetProcessPath(DWORD pid)
{
	UniqueHandle hProc(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
	if (hProc)
		return GetProcessPath(hProc.get());
	else
		return L"";
}

std::wstring GetProcessPath(HANDLE hProc)
{
	wchar_t path[MAX_PATH];
	GetProcessImageFileName(hProc, path, MAX_PATH);
	return GetWindowsPath(path);
}

std::wstring GetWindowsPath(const std::wstring& path)
{
	// path is in device form
	// \Device\HarddiskVolume2\Windows\System32\taskhost.exe
	auto pathOffset = path.find(L'\\', 1) + 1;
	pathOffset = path.find(L'\\',  pathOffset);
	std::wstring devicePath = path.substr(0, pathOffset); // \Device\HarddiskVolume2
	std::wstring dosDrive = GetDriveLetter(devicePath); // C:
	if (dosDrive.empty())
		return L"";
	std::wstring dosPath = dosDrive; // C:
	dosPath += path.substr(pathOffset); // C:\Windows\System32\taskhost.exe
	return dosPath;
}

std::wstring GetDriveLetter(const std::wstring& devicePath)
{
	for (wchar_t drive = L'A'; drive <= L'Z'; drive++)
	{
		wchar_t szDriveName[3] = { drive, L':', L'\0' };
		wchar_t szTarget[512];
		if (QueryDosDevice(szDriveName, szTarget, 512))
			if (devicePath.compare(szTarget) == 0)
				return szDriveName;
	}
	return L"";
}

std::wstring GetCode(const HookParam& hp, DWORD pid)
{
	std::wstring code(L"/H");
	WCHAR c;
	if (hp.type & PRINT_DWORD)
		c = L'H';
	else if (hp.type & USING_UNICODE)
	{
		if (hp.type & USING_STRING)
			c = L'Q';
		else if (hp.type & STRING_LAST_CHAR)
			c = L'L';
		else
			c = L'W';
	}
	else
	{
		if (hp.type & USING_STRING)
			c = L'S';
		else if (hp.type & BIG_ENDIAN)
			c = L'A';
		else if (hp.type & STRING_LAST_CHAR)
			c = L'E';
		else
			c = L'B';
	}
	code += c;
	if (hp.type & NO_CONTEXT)
		code += L'N';
	if (hp.off >> 31)
		code += L"-" + ToHexString(-(hp.off + 4));
	else
		code += ToHexString(hp.off);
	if (hp.type & DATA_INDIRECT)
	{
		if (hp.ind >> 31)
			code += L"*-" + ToHexString(-hp.ind);
		else
			code += L"*" + ToHexString(hp.ind);
	}
	if (hp.type & USING_SPLIT)
	{
		if (hp.split >> 31)
			code += L":-" + ToHexString(-(4 + hp.split));
		else
			code += L":" + ToHexString(hp.split);
	}
	if (hp.type & SPLIT_INDIRECT)
	{
		if (hp.split_ind >> 31)
			code += L"*-" + ToHexString(-hp.split_ind);
		else
			code += L"*" + ToHexString(hp.split_ind);
	}
	if (pid)
	{
		PVOID allocationBase = GetAllocationBase(pid, (LPCVOID)hp.addr);
		if (allocationBase)
		{
			std::wstring path = GetModuleFileNameAsString(pid, allocationBase);
			if (!path.empty())
			{
				auto fileName = path.substr(path.rfind(L'\\') + 1);
				DWORD relativeHookAddress = hp.addr - (DWORD)allocationBase;
				code += L"@" + ToHexString(relativeHookAddress) + L":" + fileName;
				return code;
			}
		}
	}
	if (hp.module)
	{
		code += L"@" + ToHexString(hp.addr) + L"!" + ToHexString(hp.module);
		if (hp.function)
			code += L"!" + ToHexString(hp.function);
	}
	else
	{
		// hack, the original address is stored in the function field
		// if (module == NULL && function != NULL)
		// in TextHook::UnsafeInsertHookCode() MODULE_OFFSET and FUNCTION_OFFSET are removed from
		// HookParam.type
		if (hp.function)
			code += L"@" + ToHexString(hp.function);
		else
			code += L"@" + ToHexString(hp.addr) + L":";
	}
	return code;
}

std::wstring GetModuleFileNameAsString(DWORD pid, PVOID allocationBase)
{
	const ProcessRecord* pr = man->GetProcessRecord(pid);
	if (pr)
	{
		HANDLE hProc = pr->process_handle;
		WCHAR path[MAX_PATH];
		if (GetModuleFileNameEx(hProc, (HMODULE)allocationBase, path, MAX_PATH))
			return path;
	}
	return L"";
}

PVOID GetAllocationBase(DWORD pid, LPCVOID addr)
{
	const ProcessRecord *pr = man->GetProcessRecord(pid);
	if (pr)
	{
		MEMORY_BASIC_INFORMATION info;
		HANDLE hProc = pr->process_handle;
		if (VirtualQueryEx(hProc, addr, &info, sizeof(info)))
		{
			if (info.Type & MEM_IMAGE)
				return info.AllocationBase;
		}
	}
	return NULL;
}

struct TitleParam
{
	DWORD pid, buffer_len, retn_len;
	std::wstring buffer;
};

BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lParam)
{
	TitleParam* p = (TitleParam*)lParam;
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid == p->pid)
	{
		if (GetWindowLong(hwnd, GWL_STYLE) & WS_VISIBLE)
		{
			int len = GetWindowTextLength(hwnd);
			std::unique_ptr<wchar_t[]> result(new wchar_t[len + 1]);
			GetWindowText(hwnd, result.get(), len + 1);
			p->buffer = result.get();
			p->retn_len = p->buffer.size();
			if (!p->buffer.empty())
				return FALSE;
		}
	}
	return TRUE;
}

std::wstring GetProcessTitle(DWORD pid)
{
	TitleParam p;
	p.pid = pid;
	p.buffer_len = 0;
	p.retn_len = 0;
	EnumWindows(EnumProc, (LPARAM)&p);
	return p.buffer;
}

WindowsError::WindowsError(DWORD error_code) : error_code(error_code), msg("")
{
	CHAR str[512];
	std::sprintf(str, "error code 0x%8x", error_code);
	msg = str;
}

const char *WindowsError::what() const
{
	return msg.c_str();
}

HANDLE IthCreateThread(LPVOID start_addr, DWORD param)
{
	return CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start_addr, (LPVOID)param, 0, NULL);
}

std::wstring GetModuleFileNameAsString()
{
	WCHAR path[MAX_PATH];
	GetModuleFileName(NULL, path, MAX_PATH);
	return path;
}

bool IthCreateDirectory(LPCWSTR name)
{
	std::wstring path = GetModuleFileNameAsString();
	path = path.substr(0, path.rfind(L'\\') + 1) + name;
	BOOL error_code = CreateDirectory(path.c_str(), NULL);
	return error_code != 0 || GetLastError() == ERROR_ALREADY_EXISTS;
}

HANDLE IthCreateFile(LPCWSTR name, DWORD option, DWORD share, DWORD disposition)
{
	std::wstring path = GetModuleFileNameAsString();
	path = path.substr(0, path.rfind(L'\\') + 1) + name;
	return CreateFile(path.c_str(), option, share, NULL, disposition, FILE_ATTRIBUTE_NORMAL, NULL);
}

//SJIS->Unicode. 'mb' must be null-terminated. 'wc_length' is the length of 'wc' in characters.
int MB_WC(const char* mb, wchar_t* wc, int wc_length)
{
	return MultiByteToWideChar(932, 0, mb, -1, wc, wc_length);
}

// Count characters in wide string. 'mb_length' is the number of bytes from 'mb' to convert or
// -1 if the string is null terminated.
int MB_WC_count(const char* mb, int mb_length)
{
	return MultiByteToWideChar(932, 0, mb, mb_length, NULL, 0);
}

// Unicode->SJIS. Analogous to MB_WC.
int WC_MB(const wchar_t *wc, char* mb, int mb_length)
{
	return WideCharToMultiByte(932, 0, wc, -1, mb, mb_length, NULL, NULL);
}

DWORD Hash(const std::wstring& module, int length)
{
	DWORD hash = 0;
	auto end = length < 0 || static_cast<std::size_t>(length) > module.length() ? module.end() : module.begin() + length;
	for (auto it = module.begin(); it != end; ++it)
		hash = _rotr(hash, 7) + *it;
	return hash;
}

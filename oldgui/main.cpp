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

#include "ITH.h"
#include "host.h"
#include "hookman.h"
#include "profile/Profile.h"
#include "ProfileManager.h"

HINSTANCE hIns;
ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE hInstance, DWORD nCmdShow, RECT *rc);
RECT window;
extern HWND hMainWnd; // windows.cpp
extern ProfileManager* pfman; // ProfileManager.cpp

HookManager* man;
LONG split_time;

std::map<std::wstring, long> setting;

void SaveSettings()
{
	WINDOWPLACEMENT wndpl;
	wndpl.length = sizeof(WINDOWPLACEMENT);
	GetWindowPlacement(hMainWnd, &wndpl);
	setting[L"window_left"] = wndpl.rcNormalPosition.left;
	setting[L"window_right"] = wndpl.rcNormalPosition.right;
	setting[L"window_top"] = wndpl.rcNormalPosition.top;
	setting[L"window_bottom"] = wndpl.rcNormalPosition.bottom;
	setting[L"split_time"] = split_time;

	UniqueHandle hFile(IthCreateFile(L"NextHooker.xml", GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS));
	if (hFile.get() != INVALID_HANDLE_VALUE)
	{
		FileWriter fw(hFile.get());
		pugi::xml_document doc;
		auto root = doc.root().append_child(L"NextHookerSetting");
		for (auto it = setting.begin(); it != setting.end(); ++it)
			root.append_attribute(it->first.c_str()).set_value(it->second);
		doc.save(fw);
	}
}

void DefaultSettings()
{
	setting[L"split_time"] = 200;
	setting[L"window_left"] = 100;
	setting[L"window_right"] = 800;
	setting[L"window_top"] = 100;
	setting[L"window_bottom"] = 600;
}

void InitializeSettings()
{
	split_time = setting[L"split_time"];
	window.left = setting[L"window_left"];
	window.right = setting[L"window_right"];
	window.top = setting[L"window_top"];
	window.bottom = setting[L"window_bottom"];

	if (window.right < window.left || window.right - window.left < 600)
		window.right = window.left + 600;
	if (window.bottom < window.top || window.bottom - window.top < 200)
		window.bottom = window.top + 200;
}

void LoadSettings()
{
	UniqueHandle hFile(IthCreateFile(L"NextHooker.xml", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING));
	if (hFile.get() != INVALID_HANDLE_VALUE)
	{
		DWORD size = GetFileSize(hFile.get(), NULL);
		std::unique_ptr<char[]> buffer(new char[size]);
		ReadFile(hFile.get(), buffer.get(), size, &size, NULL);
		pugi::xml_document doc;
		auto result = doc.load_buffer_inplace(buffer.get(), size);
		if (!result)
			return;
		auto root = doc.root().child(L"NextHookerSetting");
		for (auto attr = root.attributes_begin(); attr != root.attributes_end(); ++attr)
		{
			auto it = setting.find(attr->name());
			if (it != setting.end())
				it->second = std::stoul(attr->value());
		}
	}
}

extern LPCWSTR ClassName, ClassNameAdmin;
static WCHAR mutex[] = L"ITH_RUNNING";
DWORD FindITH()
{
	HWND hwnd = FindWindow(ClassName, ClassName);
	if (hwnd == NULL)
		hwnd = FindWindow(ClassName, ClassNameAdmin);
	if (hwnd)
	{
		ShowWindow(hwnd, SW_SHOWNORMAL);
		SetForegroundWindow(hwnd);
		return 0;
	}
	return 1;
}
LONG WINAPI UnhandledExcept(_EXCEPTION_POINTERS *ExceptionInfo)
{
	wchar_t path_name[512]; // fully qualified path name
	WCHAR code[16];
	EXCEPTION_RECORD* rec = ExceptionInfo->ExceptionRecord;
	std::swprintf(code, L"%08X", rec->ExceptionCode);
	MEMORY_BASIC_INFORMATION info;
	if (VirtualQuery(rec->ExceptionAddress, &info, sizeof(info)))
	{
		if (GetModuleFileName((HMODULE)info.AllocationBase, path_name, 512))
		{
			LPWSTR name = wcsrchr(path_name, L'\\');
			if (name)
			{
				DWORD addr = (DWORD)rec->ExceptionAddress;
				std::swprintf(name, L"%s:%08X", name + 1, addr - (DWORD)info.AllocationBase);
				MessageBox(NULL, name, code, MB_OK);
				TerminateProcess(GetCurrentProcess(), 0);
			}
		}
	}
	std::swprintf(path_name, L"%08X", rec->ExceptionAddress);
	MessageBox(NULL, path_name, code, MB_OK);
	TerminateProcess(GetCurrentProcess(), 0);
	return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	InitCommonControls();
	if (StartHost())
	{
		SetUnhandledExceptionFilter(UnhandledExcept);
		man = GetHostHookManager();
		pfman = new ProfileManager();
		DefaultSettings();
		LoadSettings();
		InitializeSettings();
		man->SetSplitInterval(split_time);
		hIns = hInstance;
		MyRegisterClass(hIns);
		InitInstance(hIns, FALSE, &window);
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		delete pfman;
		man = NULL;
	}
	else
	{
		FindITH();
	}
	CloseHost();
	TerminateProcess(GetCurrentProcess(), 0);
}
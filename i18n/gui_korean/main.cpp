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
#include "host/host.h"
#include "host/hookman.h"
#include "host/settings.h"
#include "CustomFilter.h"
#include "profile/Profile.h"
#include "ProfileManager.h"

HINSTANCE hIns;
ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE hInstance, DWORD nCmdShow, RECT *rc);
RECT window;
extern HWND hMainWnd; // windows.cpp
extern bool MonitorFlag; // ProfileManager.cpp
extern ProfileManager* pfman; // ProfileManager.cpp

extern "C" {
	BOOL IthInitSystemService();
	void IthCloseSystemService();
}

CustomFilter* uni_filter;
CustomFilter* mb_filter;
HookManager* man;
Settings* setman;
LONG split_time, cyclic_remove, global_filter;
LONG process_time, inject_delay, insert_delay,
auto_inject, auto_insert, clipboard_flag;

std::map<std::wstring, long> setting;

void RecordMBChar(WORD mb, PVOID f)
{
	auto filter = (pugi::xml_node*)f;
	DWORD m = mb;
	WCHAR buffer[16];
	std::swprintf(buffer, L"m%04X", m);
	filter->append_attribute(buffer) = L"0";
}

void RecordUniChar(WORD uni, PVOID f)
{
	auto filter = (pugi::xml_node*)f;
	DWORD m = uni;
	WCHAR buffer[16];
	std::swprintf(buffer, L"u%04X", m);
	filter->append_attribute(buffer) = L"0";
	std::wstring text = filter->text().get();
	text += (wchar_t)m;
	filter->text().set(text.c_str());
}

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
	setting[L"process_time"] = process_time;
	setting[L"inject_delay"] = inject_delay;
	setting[L"insert_delay"] = insert_delay;
	setting[L"auto_inject"] = auto_inject;
	setting[L"auto_insert"] = auto_insert;
	setting[L"auto_copy"] = clipboard_flag;
	setting[L"auto_suppress"] = cyclic_remove;
	setting[L"global_filter"] = global_filter;

	UniqueHandle hFile(IthCreateFile(L"ITH.xml", GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS));
	if (hFile.get() != INVALID_HANDLE_VALUE)
	{
		FileWriter fw(hFile.get());
		pugi::xml_document doc;
		auto root = doc.root().append_child(L"ITH_Setting");
		for (auto it = setting.begin(); it != setting.end(); ++it)
			root.append_attribute(it->first.c_str()).set_value(it->second);
		auto filter = root.append_child(L"SingleCharFilter");
		filter.append_child(pugi::xml_node_type::node_pcdata);
		mb_filter->Traverse(RecordMBChar, &filter);
		uni_filter->Traverse(RecordUniChar, &filter);
		doc.save(fw);
	}
}

void DefaultSettings()
{
	setting[L"split_time"] = 200;
	setting[L"process_time"] = 50;
	setting[L"inject_delay"] = 3000;
	setting[L"insert_delay"] = 500;
	setting[L"auto_inject"] = 1;
	setting[L"auto_insert"] = 1;
	setting[L"auto_copy"] = 0;
	setting[L"auto_suppress"] = 0;
	setting[L"global_filter"] = 0;
	setting[L"window_left"] = 100;
	setting[L"window_right"] = 800;
	setting[L"window_top"] = 100;
	setting[L"window_bottom"] = 600;
}

void InitializeSettings()
{
	split_time = setting[L"split_time"];
	process_time = setting[L"process_time"];
	inject_delay = setting[L"inject_delay"];
	insert_delay = setting[L"insert_delay"];
	auto_inject = setting[L"auto_inject"];
	auto_insert = setting[L"auto_insert"];
	clipboard_flag = setting[L"auto_copy"];
	cyclic_remove = setting[L"auto_suppress"];
	global_filter = setting[L"global_filter"];
	window.left = setting[L"window_left"];
	window.right = setting[L"window_right"];
	window.top = setting[L"window_top"];
	window.bottom = setting[L"window_bottom"];

	if (auto_inject > 1)
		auto_inject = 1;
	if (auto_insert > 1)
		auto_insert = 1;
	if (clipboard_flag > 1)
		clipboard_flag = 1;
	if (cyclic_remove > 1)
		cyclic_remove = 1;

	if (window.right < window.left || window.right - window.left < 600)
		window.right = window.left + 600;
	if (window.bottom < window.top || window.bottom - window.top < 200)
		window.bottom = window.top + 200;
}

void LoadSettings()
{
	UniqueHandle hFile(IthCreateFile(L"ITH.xml", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING));
	if (hFile.get() != INVALID_HANDLE_VALUE)
	{
		DWORD size = GetFileSize(hFile.get(), NULL);
		std::unique_ptr<char[]> buffer(new char[size]);
		ReadFile(hFile.get(), buffer.get(), size, &size, NULL);
		pugi::xml_document doc;
		auto result = doc.load_buffer_inplace(buffer.get(), size);
		if (!result)
			return;
		auto root = doc.root().child(L"ITH_Setting");
		for (auto attr = root.attributes_begin(); attr != root.attributes_end(); ++attr)
		{
			auto it = setting.find(attr->name());
			if (it != setting.end())
				it->second = std::stoul(attr->value());
		}
		auto filter = root.child(L"SingleCharFilter");
		if (filter)
		{
			for (auto attr = filter.attributes_begin(); attr != filter.attributes_end(); ++attr)
			{
				if (attr->name()[0] == L'm')
				{
					DWORD c = std::stoul(attr->name() + 1, NULL, 16);
					mb_filter->Insert(c & 0xFFFF);
				}
				else if (attr->name()[0] == L'u')
				{
					DWORD c = std::stoul(attr->name() + 1, NULL, 16);
					uni_filter->Insert(c & 0xFFFF);
				}
			}
			std::wstring filter_value = filter.text().get();
			for (auto it = filter_value.begin(); it != filter_value.end(); ++it)
			{
				WCHAR filter_unichar[2] = { *it, L'\0' };
				char filter_mbchar[4];
				WC_MB(filter_unichar, filter_mbchar, 4);
				mb_filter->Insert(*(WORD*)filter_mbchar);
				uni_filter->Insert(*it);
			}
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
	if (!IthInitSystemService())
		TerminateProcess(GetCurrentProcess(), 0);
	CreateMutex(NULL, TRUE, L"ITH_MAIN_RUNNING");
	if (OpenHost())
	{
		SetUnhandledExceptionFilter(UnhandledExcept);
		GetHostHookManager(&man);
		GetHostSettings(&setman);
		setman->splittingInterval = 200;
		MonitorFlag = true;
		pfman = new ProfileManager();
		mb_filter = new CustomFilter();
		uni_filter = new CustomFilter();
		DefaultSettings();
		LoadSettings();
		InitializeSettings();
		setman->splittingInterval = split_time;
		setman->clipboardFlag = clipboard_flag > 0;
		hIns = hInstance;
		MyRegisterClass(hIns);
		InitInstance(hIns, FALSE, &window);
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		//delete mb_filter;
		//delete uni_filter;
		delete pfman;
		MonitorFlag = false;
		man = NULL;
	}
	else
	{
		FindITH();
	}
	CloseHost();
	IthCloseSystemService();
	TerminateProcess(GetCurrentProcess(), 0);
}

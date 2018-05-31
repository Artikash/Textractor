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
#include "window.h"
#include "ProcessWindow.h"
#include "resource.h"
#include "language.h"
#include "host/host.h"
#include "host/hookman.h"
#include "vnrhook/include/const.h"
#include "version.h"
#include "ProfileManager.h"
#include "host/settings.h"
#include "CustomFilter.h"
#include "profile/Profile.h"
#include "TextBuffer.h"
#include "profile/misc.h"

#define CMD_SIZE 512

static WNDPROC proc, proccmd, procChar;
static WCHAR last_cmd[CMD_SIZE];
extern HINSTANCE hIns; // main.cpp

HWND hMainWnd, hwndCombo, hwndProcessComboBox, hwndEdit, hwndCmd;
HWND hwndProcess;
HWND hwndOption, hwndTop, hwndClear, hwndSave, hwndRemoveLink, hwndRemoveHook;
HWND hProcDlg, hOptionDlg;
HBRUSH hWhiteBrush;
DWORD background;
ProcessWindow* pswnd;
TextBuffer* texts;
extern ProfileManager* pfman; // ProfileManager.cpp
extern HookManager* man; // main.cpp
extern CustomFilter* mb_filter; // main.cpp
extern CustomFilter* uni_filter; // main.cpp
extern Settings* setman; // main.cpp
#define COMMENT_BUFFER_LENGTH 512
static WCHAR comment_buffer[COMMENT_BUFFER_LENGTH];

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
void SaveSettings(); // main.cpp
extern LONG split_time, process_time, inject_delay, insert_delay,
auto_inject, auto_insert, clipboard_flag, cyclic_remove, global_filter; //main.cpp
static int last_select, last_edit;

ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = NULL;
	wcex.hCursor = NULL;
	wcex.hbrBackground = GetStockBrush(WHITE_BRUSH);
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = ClassName;
	wcex.hIconSm = LoadIcon(hInstance, (LPWSTR)IDI_ICON1);
	return RegisterClassEx(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, DWORD nAdmin, RECT* rc)
{
	hIns = hInstance;
	LPCWSTR name = (nAdmin) ? ClassNameAdmin : ClassName;
	hMainWnd = CreateWindow(ClassName, name, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
		rc->left, rc->top, rc->right - rc->left, rc->bottom - rc->top, NULL, NULL, hInstance, 0);
	if (!hMainWnd)
		return FALSE;
	ShowWindow(hMainWnd, SW_SHOWNORMAL);
	UpdateWindow(hMainWnd);
	return TRUE;
}

DWORD SaveProcessProfile(DWORD pid); // ProfileManager.cpp

BOOL CALLBACK OptionDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		SetWindowText(GetDlgItem(hDlg, IDC_EDIT1), std::to_wstring((long long)split_time).c_str());
		SetWindowText(GetDlgItem(hDlg, IDC_EDIT2), std::to_wstring((long long)process_time).c_str());
		SetWindowText(GetDlgItem(hDlg, IDC_EDIT3), std::to_wstring((long long)inject_delay).c_str());
		SetWindowText(GetDlgItem(hDlg, IDC_EDIT4), std::to_wstring((long long)insert_delay).c_str());
		CheckDlgButton(hDlg, IDC_CHECK1, auto_inject);
		CheckDlgButton(hDlg, IDC_CHECK2, auto_insert);
		CheckDlgButton(hDlg, IDC_CHECK3, clipboard_flag);
		CheckDlgButton(hDlg, IDC_CHECK4, cyclic_remove);
		CheckDlgButton(hDlg, IDC_CHECK5, global_filter);
	}
	return TRUE;
	case WM_COMMAND:
	{
		DWORD wmId = LOWORD(wParam);
		DWORD wmEvent = HIWORD(wParam);
		switch (wmId)
		{
		case IDOK:
		{
			WCHAR str[128];
			GetWindowText(GetDlgItem(hDlg, IDC_EDIT1), str, 0x80);
			DWORD st = std::stoul(str);
			split_time = st > 100 ? st : 100;
			GetWindowText(GetDlgItem(hDlg, IDC_EDIT2), str, 0x80);
			DWORD pt = std::stoul(str);
			process_time = pt > 50 ? pt : 50;
			GetWindowText(GetDlgItem(hDlg, IDC_EDIT3), str, 0x80);
			DWORD jd = std::stoul(str);
			inject_delay = jd > 1000 ? jd : 1000;
			GetWindowText(GetDlgItem(hDlg, IDC_EDIT4), str, 0x80);
			DWORD sd = std::stoul(str);
			insert_delay = sd > 200 ? sd : 200;
			if (IsDlgButtonChecked(hDlg, IDC_CHECK6))
			{
				man->ResetRepeatStatus();
			}
			auto_inject = IsDlgButtonChecked(hDlg, IDC_CHECK1);
			auto_insert = IsDlgButtonChecked(hDlg, IDC_CHECK2);
			clipboard_flag = IsDlgButtonChecked(hDlg, IDC_CHECK3);
			cyclic_remove = IsDlgButtonChecked(hDlg, IDC_CHECK4);
			global_filter = IsDlgButtonChecked(hDlg, IDC_CHECK5);
			setman->clipboardFlag = clipboard_flag;
			setman->splittingInterval = split_time;
			if (auto_inject == 0) auto_insert = 0;
		}
		case IDCANCEL:
			EndDialog(hDlg, 0);
			hOptionDlg = NULL;
			break;
		}
		return TRUE;
	}
	default:
		return FALSE;
	}
	return FALSE;
}

BOOL CALLBACK ProcessDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		pswnd = new ProcessWindow(hDlg);
		return TRUE;
	}
	case WM_COMMAND:
	{
		DWORD wmId, wmEvent;
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		switch (wmId)
		{
		case WM_DESTROY:
		case IDOK:
			EndDialog(hDlg, NULL);
			hProcDlg = NULL;
			delete pswnd;
			pswnd = NULL;
			break;
		case IDC_BUTTON1:
			pswnd->RefreshProcess();
			break;
		case IDC_BUTTON2:
			pswnd->AttachProcess();
			break;
		case IDC_BUTTON3:
			pswnd->DetachProcess();
			break;
		case IDC_BUTTON5:
            pswnd->CreateProfileForSelectedProcess();
			break;
		case IDC_BUTTON6:
            pswnd->DeleteProfileForSelectedProcess();
			break;
		}
	}
	return TRUE;

	case WM_NOTIFY:
	{
		LPNMHDR dr = (LPNMHDR)lParam;
		switch (dr->code)
		{
		case LVN_ITEMCHANGED:
			if (dr->idFrom == IDC_LIST1)
			{
				NMLISTVIEW *nmlv = (LPNMLISTVIEW)lParam;
				if (nmlv->uNewState & LVIS_SELECTED)
					pswnd->RefreshThread(nmlv->iItem);
			}
			break;
		}
	}
	return TRUE;
	default:
		return FALSE;
	}
}

LRESULT CALLBACK EditProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{

	switch (message)
	{
	case WM_CHAR:  //Filter user input.
		if (GetKeyState(VK_CONTROL) & 0x8000)
		{
			if (wParam == 1)
			{
				Edit_SetSel(hwndEdit, 0, -1);
				SendMessage(hwndEdit, WM_COPY, 0, 0);
			}
		}
		return 0;
	case WM_LBUTTONUP:
		if (hwndEdit)
			SendMessage(hwndEdit, WM_COPY, 0, 0);
	default:
	{
		return proc(hWnd, message, wParam, lParam);
	}

	}
}

LRESULT CALLBACK EditCmdProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_KEYDOWN:
		if (wParam == VK_UP)
		{
			SetWindowText(hWnd, last_cmd);
			SetFocus(hWnd);
			return 0;
		}
		break;
	case WM_CHAR:
		if (wParam == VK_RETURN)
		{
			DWORD s = 0, pid = 0;
			WCHAR str[32];
			if (GetWindowTextLength(hWnd) == 0)
				break;
			GetWindowText(hWnd, last_cmd, CMD_SIZE);
			//IthBreak();
			if (GetWindowText(hwndProcessComboBox, str, 32))
				pid = std::stoul(str);
			ProcessCommand(last_cmd, pid);
			Edit_SetSel(hWnd, 0, -1);
			Edit_ReplaceSel(hWnd, &s);
			SetFocus(hWnd);
			return 0;
		}
	default:
		break;
	}
	return CallWindowProc(proccmd, hWnd, message, wParam, lParam);
}

void CreateButtons(HWND hWnd)
{
	hwndProcess = CreateWindow(L"Button", L"Process", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndOption = CreateWindow(L"Button", L"Option", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndClear = CreateWindow(L"Button", L"Clear", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndSave = CreateWindow(L"Button", L"Save", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndRemoveLink = CreateWindow(L"Button", L"Unlink", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndRemoveHook = CreateWindow(L"Button", L"Unhook", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndTop = CreateWindow(L"Button", L"Top", WS_CHILD | WS_VISIBLE | BS_PUSHLIKE | BS_CHECKBOX,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndProcessComboBox = CreateWindow(L"ComboBox", NULL,
		WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST |
		CBS_SORT | WS_VSCROLL | WS_TABSTOP,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndCmd = CreateWindowEx(WS_EX_CLIENTEDGE, L"Edit", NULL,
		WS_CHILD | WS_VISIBLE | ES_NOHIDESEL | ES_LEFT | ES_AUTOHSCROLL,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndEdit = CreateWindowEx(WS_EX_CLIENTEDGE, L"Edit", NULL,
		WS_CHILD | WS_VISIBLE | ES_NOHIDESEL | WS_VSCROLL |
		ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
}

void ClickButton(HWND hWnd, HWND h)
{
	if (h == hwndProcess)
	{
		if (hProcDlg)
			SetForegroundWindow(hProcDlg);
		else
			hProcDlg = CreateDialog(hIns, (LPWSTR)IDD_DIALOG2, 0, ProcessDlgProc);
	}
	else if (h == hwndOption)
	{
		if (hOptionDlg)
			SetForegroundWindow(hOptionDlg);
		else
			hOptionDlg = CreateDialog(hIns, (LPWSTR)IDD_DIALOG4, 0, OptionDlgProc);
	}
	else if (h == hwndClear)
	{
		WCHAR pwcEntry[128] = {};
		DWORD dwId = ComboBox_GetCurSel(hwndCombo);
		int len = ComboBox_GetLBText(hwndCombo, dwId, pwcEntry);
		dwId = std::stoul(pwcEntry, NULL, 16);
		if (dwId == 0)
			man->ClearCurrent();
		else
			man->RemoveSingleThread(dwId);
	}
	else if (h == hwndTop)
	{
		if (Button_GetCheck(h) == BST_CHECKED)
		{
			Button_SetCheck(h, BST_UNCHECKED);
			SetWindowPos(hWnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hProcDlg)
				SetWindowPos(hProcDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hOptionDlg)
				SetWindowPos(hOptionDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
		}
		else
		{
			Button_SetCheck(h, BST_CHECKED);
			SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hProcDlg)
				SetWindowPos(hProcDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hOptionDlg)
				SetWindowPos(hOptionDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
		}
	}
	else if (h == hwndSave)
	{
		WCHAR str[32];
		if (GetWindowText(hwndProcessComboBox, str, 32))
		{
			DWORD pid = std::stoul(str);
			SaveProcessProfile(pid);
		}
		pfman->SaveProfiles();
	}
	else if (h == hwndRemoveLink)
	{
		WCHAR str[32];
		if (GetWindowText(hwndCombo, str, 32))
		{
			DWORD from = std::stoul(str, NULL, 16);
			if (from != 0)
				Host_UnLink(from);
		}
	}
	else if (h == hwndRemoveHook)
	{
		WCHAR str[32];
		if (GetWindowText(hwndCombo, str, 32))
		{
			std::wstring entry(str);
			std::size_t i;
			DWORD threadNumber = std::stoul(entry, &i, 16);
			entry = entry.substr(i + 1);
			DWORD pid = std::stoul(entry, &i);
			entry = entry.substr(i + 1);
			DWORD addr = std::stoul(entry, NULL, 16);
			if (threadNumber != 0)
				Host_RemoveHook(pid, addr);
		}
	}
}

DWORD ThreadFilter(TextThread* thread, BYTE* out, DWORD len, DWORD new_line, PVOID data, bool space)
{
	DWORD status = thread->Status();
	if (global_filter && !new_line && thread->Number() != 0)
	{
		if (status & USING_UNICODE)
		{
			DWORD i, j;
			len /= 2;
			LPWSTR str = (LPWSTR)out;
			for (i = 0, j = 0; i < len; i++)
			{
				WCHAR c = str[i];
				if (!uni_filter->Find(c))
					str[j++] = c;
			}
			memset(str + j, 0, (len - j) * 2);
			len = j * 2;
		}
		else
		{
			DWORD i, j;
			for (i = 0, j = 0; i < len; i++)
			{
				WORD c = out[i];
				if (!IsDBCSLeadByte(c & 0xFF))
				{
					if (!mb_filter->Find(c))
						out[j++] = c & 0xFF;
				}
				else if (i + 1 < len)
				{

					c = out[i + 1];
					c <<= 8;
					c |= out[i];
					if (!mb_filter->Find(c))
					{
						out[j++] = c & 0xFF;
						out[j++] = c >> 8;
					}
					i++;
				}
			}
			memset(out + j, 0, len - j);
			len = j;
		}
	}
	return len;
}

DWORD ThreadOutput(TextThread* thread, BYTE* out, DWORD len, DWORD new_line, PVOID data, bool space)
{
	if (len == 0)
		return len;
	DWORD status = thread->Status();
	if (status & CURRENT_SELECT)
	{
		if (new_line)
		{
			if (thread->Number() == 0)
				texts->AddText(L"\r\n", 2, true);
			else
				texts->AddText(L"\r\n\r\n", 4, true);
		}
		else if (status & USING_UNICODE)
		{
			texts->AddText((LPWSTR)out, len / 2, false);
		}
		else
		{
			int uni_len = MB_WC_count((char*)out, len);
			LPWSTR str = new WCHAR[uni_len + 1];
			MB_WC((char*)out, str, uni_len + 1);
			str[uni_len] = L'\0';
			texts->AddText(str, uni_len, false);
			delete str;
		}
	}
	return len;
}

bool GetHookParam(DWORD pid, DWORD hook_addr, HookParam& hp)
{
	if (!pid)
		return false;
	ProcessRecord *pr = ::man->GetProcessRecord(pid);
	if (!pr)
		return false;
	bool result = false;
	WaitForSingleObject(pr->hookman_mutex, 0);
	const Hook *hks = (Hook *)pr->hookman_map;
	for (int i = 0; i < MAX_HOOK; i++)
	{
		if (hks[i].Address() == hook_addr)
		{
			hp = hks[i].hp;
			result = true;
			break;
		}
	}
	ReleaseMutex(pr->hookman_mutex);
	return result;
}

std::wstring GetEntryString(TextThread& thread)
{
	CHAR entry[512];
	thread.GetEntryString(entry, 512);
	return toUnicodeString(entry);
}

std::wstring CreateEntryWithLink(TextThread& thread, std::wstring& entry)
{
	std::wstring entryWithLink = entry;
	if (thread.Link())
		entryWithLink += L"->" + ToHexString(thread.LinkNumber());
	if (thread.PID() == 0)
		entryWithLink += L"ConsoleOutput";
	HookParam hp = {};
	if (GetHookParam(thread.PID(), thread.Addr(), hp))
		entryWithLink += L" (" + GetCode(hp, thread.PID()) + L")";
	return entryWithLink;
}

void AddToCombo(TextThread& thread, bool replace)
{
	std::wstring entry = GetEntryString(thread);
	std::wstring entryWithLink = CreateEntryWithLink(thread, entry);
	int i = ComboBox_FindString(hwndCombo, -1, entry.c_str());
	if (replace)
	{
		int sel = ComboBox_GetCurSel(hwndCombo);
		if (i != CB_ERR)
			ComboBox_DeleteString(hwndCombo, i);
		ComboBox_AddString(hwndCombo, entryWithLink.c_str());
		ComboBox_SetCurSel(hwndCombo, sel);
	}
	else
	{
		if (i == CB_ERR)
			ComboBox_AddString(hwndCombo, entryWithLink.c_str());
		// Why set current selection to 0 when the new thread is selected?
		if (thread.Status() & CURRENT_SELECT)
			ComboBox_SetCurSel(hwndCombo, 0);
	}
}

void RemoveFromCombo(TextThread* thread)
{
	CHAR entry[512];
	thread->GetEntryString(entry, 512);
	std::wstring unicodeEntry = toUnicodeString(entry);
	if (thread->PID() == 0)
		unicodeEntry += L"ConsoleOutput";
	int i = ComboBox_FindString(hwndCombo, 0, unicodeEntry.c_str());
	if (i != CB_ERR)
	{
		if (ComboBox_DeleteString(hwndCombo, i) == CB_ERR)
			ConsoleOutput(ErrorDeleteCombo);
	}
}

void ComboSelectCurrent(TextThread* thread)
{
	ComboBox_SetCurSel(hwndCombo, thread->Number());
}

DWORD SetEditText(LPWSTR wc)
{
	DWORD line;
	Edit_SetText(hwndEdit, wc);
	line = Edit_GetLineCount(hwndEdit);
	SendMessage(hwndEdit, EM_LINESCROLL, 0, line);
	return 0;
}

DWORD ThreadReset(TextThread* thread)
{
	texts->ClearBuffer();
	man->SetCurrent(thread);
	thread->LockVector();
	DWORD uni = thread->Status() & USING_UNICODE;
	if (uni)
	{
		DWORD len = 0;
		LPWSTR wc = (LPWSTR)thread->GetStore(&len);
		len /= 2;
		wc[len] = L'\0';
		SetEditText(wc);
	}
	else
	{
		DWORD len = MB_WC_count((char*)thread->Storage(), thread->Used());
		LPWSTR wc = new WCHAR[len + 1];
		MB_WC((char*)thread->Storage(), wc, len + 1);
		wc[len] = L'\0';
		SetEditText(wc);
		delete wc;
	}
	WCHAR buffer[16];
	std::swprintf(buffer, L"%04X", thread->Number());
	DWORD tmp = ComboBox_FindString(hwndCombo, 0, buffer);
	if (tmp != CB_ERR)
		ComboBox_SetCurSel(hwndCombo, tmp);
	thread->UnlockVector();
	return 0;
}

DWORD AddRemoveLink(TextThread* thread)
{
	AddToCombo(*thread, true);
	return 0;
}

bool IsUnicodeHook(const ProcessRecord& pr, DWORD hook);
void AddLinksToHookManager(const Profile* pf, size_t thread_index, const TextThread* thread);

DWORD ThreadCreate(TextThread* thread)
{
	thread->RegisterOutputCallBack(ThreadOutput, 0);
	thread->RegisterFilterCallBack(ThreadFilter, 0);
	AddToCombo(*thread, false);
	const auto& tp = thread->GetThreadParameter();
	auto pr = man->GetProcessRecord(tp->pid);
	if (pr == NULL)
		return 0;
	if (IsUnicodeHook(*pr, tp->hook))
		thread->Status() |= USING_UNICODE;
	auto pf = pfman->GetProfile(tp->pid);
	if (!pf)
		return 0;
	const std::wstring& hook_name = GetHookNameByAddress(*pr, thread->GetThreadParameter()->hook);
	auto thread_profile = pf->FindThread(thread->GetThreadParameter(), hook_name);
	if (thread_profile != pf->Threads().end())
	{
		(*thread_profile)->HookManagerIndex() = thread->Number();
		auto thread_index = thread_profile - pf->Threads().begin();
		AddLinksToHookManager(pf, thread_index, thread);
		if (pf->IsThreadSelected(thread_profile))
			ThreadReset(thread);
	}
	return 0;
}

bool IsUnicodeHook(const ProcessRecord& pr, DWORD hook)
{
	bool res = false;
	WaitForSingleObject(pr.hookman_mutex, 0);
	auto hooks = (const Hook*)pr.hookman_map;
	for (DWORD i = 0; i < MAX_HOOK; i++)
	{
		if (hooks[i].Address() == hook)
		{
			res = hooks[i].Type() & USING_UNICODE;
			break;
		}
	}
	ReleaseMutex(pr.hookman_mutex);
	return res;
}

void AddLinksToHookManager(const Profile* pf, size_t thread_index, const TextThread* thread)
{
	for (auto lp = pf->Links().begin(); lp != pf->Links().end(); ++lp)
	{
		if ((*lp)->FromIndex() == thread_index)
		{
			WORD to_index = pf->Threads()[(*lp)->ToIndex()]->HookManagerIndex();
			if (to_index != 0)
				man->AddLink(thread->Number(), to_index);
		}
		if ((*lp)->ToIndex() == thread_index)
		{
			WORD from_index = pf->Threads()[(*lp)->FromIndex()]->HookManagerIndex();
			if (from_index != 0)
				man->AddLink(from_index, thread->Number());
		}
	}
}

DWORD ThreadRemove(TextThread* thread)
{
	RemoveFromCombo(thread);
	return 0;
}

DWORD RegisterProcessList(DWORD pid)
{
	auto path = GetProcessPath(pid);
	if (!path.empty())
	{
		WCHAR str[MAX_PATH];
		std::swprintf(str, L"%04d:%s", pid, path.substr(path.rfind(L'\\') + 1).c_str());
		ComboBox_AddString(hwndProcessComboBox, str);
		if (ComboBox_GetCount(hwndProcessComboBox) == 1)
			ComboBox_SetCurSel(hwndProcessComboBox, 0);
	}
	return 0;
}

DWORD RemoveProcessList(DWORD pid)
{
	WCHAR str[MAX_PATH];
	std::swprintf(str, L"%04d", pid);
	DWORD i = ComboBox_FindString(hwndProcessComboBox, 0, str);
	DWORD j = ComboBox_GetCurSel(hwndProcessComboBox);
	if (i != CB_ERR)
	{
		DWORD k = ComboBox_DeleteString(hwndProcessComboBox, i);
		if (i == j)
			ComboBox_SetCurSel(hwndProcessComboBox, 0);
	}
	return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_CREATE:
		CreateButtons(hWnd);
		// Add text to the window.
		Edit_LimitText(hwndEdit, -1);
		SendMessage(hwndEdit, WM_INPUTLANGCHANGEREQUEST, 0, 0x411);
		proc = (WNDPROC)SetWindowLong(hwndEdit, GWL_WNDPROC, (LONG)EditProc);
		proccmd = (WNDPROC)SetWindowLong(hwndCmd, GWL_WNDPROC, (LONG)EditCmdProc);
		hwndCombo = CreateWindow(L"ComboBox", NULL,
			WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST |
			CBS_SORT | WS_VSCROLL | WS_TABSTOP,
			0, 0, 0, 0, hWnd, 0, hIns, NULL);
		{
			HDC hDC = GetDC(hWnd);
			int nHeight = -MulDiv(12, GetDeviceCaps(hDC, LOGPIXELSY), 72);
			ReleaseDC(hWnd, hDC);
			HFONT hf = CreateFont(nHeight, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE, SHIFTJIS_CHARSET,
				OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
				L"MS Gothic");
			hWhiteBrush = GetStockBrush(WHITE_BRUSH);
			SendMessage(hwndCmd, WM_SETFONT, (WPARAM)hf, 0);
			SendMessage(hwndEdit, WM_SETFONT, (WPARAM)hf, 0);
			SendMessage(hwndCombo, WM_SETFONT, (WPARAM)hf, 0);
			SendMessage(hwndProcessComboBox, WM_SETFONT, (WPARAM)hf, 0);
			texts = new TextBuffer(hwndEdit);
			man->RegisterThreadCreateCallback(ThreadCreate);
			man->RegisterThreadRemoveCallback(ThreadRemove);
			man->RegisterThreadResetCallback(ThreadReset);
			TextThread* console = man->FindSingle(0);
			console->RegisterOutputCallBack(ThreadOutput, NULL);
			AddToCombo(*console, false);
			man->RegisterProcessAttachCallback(RegisterProcessList);
			man->RegisterProcessDetachCallback(RemoveProcessList);
			//man->RegisterProcessNewHookCallback(RefreshProfileOnNewHook); Artikash 5/30/2018 TODO: Finish implementing this.
			man->RegisterAddRemoveLinkCallback(AddRemoveLink);
			man->RegisterConsoleCallback(ConsoleOutput);
			StartHost();
			{
				static const WCHAR program_name[] = L"Interactive Text Hooker";
				//static const WCHAR program_version[] = L"3.0";
				static WCHAR version_info[256];
				std::swprintf(version_info, L"%s %s (%s)", program_name, program_version, build_date);
				man->AddConsoleOutput(version_info);
				man->AddConsoleOutput(InitMessage);
			}

			if (background == 0)
				man->AddConsoleOutput(BackgroundMsg);
		}

		return 0;
	case WM_COMMAND:
	{
		DWORD wmId, wmEvent, dwId;
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		switch (wmEvent)
		{
		case EN_VSCROLL:
		{
			SCROLLBARINFO info = { sizeof(info) };
			GetScrollBarInfo(hwndEdit, OBJID_VSCROLL, &info);
			InvalidateRect(hwndEdit, 0, 1);
			ValidateRect(hwndEdit, &info.rcScrollBar);
			RedrawWindow(hwndEdit, 0, 0, RDW_ERASE);
		}
		break;
		case CBN_SELENDOK:
		{
			if ((HWND)lParam == hwndProcessComboBox)
				return 0;
			dwId = ComboBox_GetCurSel(hwndCombo);
			int len = ComboBox_GetLBTextLen(hwndCombo, dwId);
			if (len > 0)
			{
				LPWSTR pwcEntry = new WCHAR[len + 1];
				len = ComboBox_GetLBText(hwndCombo, dwId, pwcEntry);
				DWORD num = std::stoul(pwcEntry, NULL, 16);
				man->SelectCurrent(num);
				delete[] pwcEntry;
			}
		}
		return 0;
		case BN_CLICKED:
			ClickButton(hWnd, (HWND)lParam);
			break;
		default:
			break;
		}
	}
	break;
	case WM_SETFOCUS:
		SetFocus(hwndEdit);
		return 0;
	case WM_SIZE:
	{
		WORD width = LOWORD(lParam);
		WORD height = HIWORD(lParam);
		DWORD l = width / 7;
		WORD h = HIWORD(GetDialogBaseUnits()); // height of the system font
		h = h + (h / 2);
		HDC hDC = GetDC(hWnd);
		RECT rc;
		GetClientRect(hWnd, &rc);
		FillRect(hDC, &rc, hWhiteBrush);
		ReleaseDC(hWnd, hDC);
		MoveWindow(hwndProcess, 0, 0, l, h, TRUE);
		MoveWindow(hwndOption, l * 1, 0, l, h, TRUE);
		MoveWindow(hwndTop, l * 2, 0, l, h, TRUE);
		MoveWindow(hwndClear, l * 3, 0, l, h, TRUE);
		MoveWindow(hwndRemoveLink, l * 4, 0, l, h, TRUE);
		MoveWindow(hwndRemoveHook, l * 5, 0, l, h, TRUE);
		MoveWindow(hwndSave, l * 6, 0, width - 6 * l, h, TRUE);
		l *= 2;
		MoveWindow(hwndProcessComboBox, 0, h, l, 200, TRUE);
		MoveWindow(hwndCmd, l, h, width - l, h, TRUE);
		MoveWindow(hwndCombo, 0, h * 2, width, 200, TRUE);
		h *= 3;
		MoveWindow(hwndEdit, 0, h, width, height - h, TRUE);
	}
	return 0;
	case WM_DESTROY:
		man->RegisterThreadCreateCallback(0);
		man->RegisterThreadRemoveCallback(0);
		man->RegisterThreadResetCallback(0);
		man->RegisterProcessAttachCallback(0);
		man->RegisterProcessDetachCallback(0);
		//delete texts;
		SaveSettings();
		PostQuitMessage(0);
		return 0;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

DWORD WINAPI FlushThread(LPVOID lParam)
{
	TextBuffer* t = (TextBuffer*)lParam;
	while (t->Running())
	{
		t->Flush();
		Sleep(10);
	}
	return 0;
}

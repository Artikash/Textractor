#include "ProcessWindow.h"
#include "resource.h"
#include "host.h"
#include "hookman.h"
#include "ProfileManager.h"
#include "profile/Profile.h"

extern HookManager* man; // main.cpp
extern ProfileManager* pfman; // ProfileManager.cpp

ProcessWindow::ProcessWindow(HWND hDialog) : hDlg(hDialog)
{
	hbRefresh = GetDlgItem(hDlg, IDC_BUTTON1);
	hbAttach = GetDlgItem(hDlg, IDC_BUTTON2);
	hbDetach = GetDlgItem(hDlg, IDC_BUTTON3);
	hbAddProfile = GetDlgItem(hDlg, IDC_BUTTON5);
	hbRemoveProfile = GetDlgItem(hDlg, IDC_BUTTON6);
	EnableWindow(hbAddProfile, FALSE);
	EnableWindow(hbRemoveProfile, FALSE);
	hlProcess = GetDlgItem(hDlg, IDC_LIST1);
	heOutput = GetDlgItem(hDlg, IDC_EDIT1);
	ListView_SetExtendedListViewStyleEx(hlProcess, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	InitProcessDlg();
	RefreshProcess();
	EnableWindow(hbDetach, FALSE);
	EnableWindow(hbAttach, FALSE);
}

void ProcessWindow::InitProcessDlg()
{
	LVCOLUMN lvc = {};
	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH;
	lvc.fmt = LVCFMT_RIGHT;  // left-aligned column
	lvc.cx = 40;
	lvc.pszText = L"PID";
	ListView_InsertColumn(hlProcess, 0, &lvc);
	lvc.cx = 100;
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.pszText = L"Name";
	ListView_InsertColumn(hlProcess, 1, &lvc);
}

void ProcessWindow::RefreshProcess()
{
	ListView_DeleteAllItems(hlProcess);
	LVITEM item = {};
	item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE;
	DWORD idProcess[1024], cbNeeded;
	WCHAR path[MAX_PATH];

	if (EnumProcesses(idProcess, sizeof(idProcess), &cbNeeded))
	{
		DWORD len = cbNeeded / sizeof(DWORD);
		for (DWORD i = 0; i < len; ++i)
		{
			DWORD pid = idProcess[i];
			UniqueHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
			if (hProcess)
			{
				if (GetProcessImageFileName(hProcess.get(), path, MAX_PATH))
				{
					WCHAR buffer[256];
					std::swprintf(buffer, L"%d", pid);
					PWCHAR name = wcsrchr(path, L'\\') + 1;
					item.pszText = buffer;
					item.lParam = pid;
					ListView_InsertItem(hlProcess, &item);
					ListView_SetItemText(hlProcess, item.iItem, 1, name);
				}
			}
		}
	}
}

void ProcessWindow::AttachProcess()
{
	DWORD pid = GetSelectedPID();
	if (InjectProcess(pid))
		RefreshThreadWithPID(pid, true);
	else
		ConsoleOutput(L"NextHooker: could not inject");
}

void ProcessWindow::DetachProcess()
{
	DWORD pid = GetSelectedPID();
	::DetachProcess(pid);
	RefreshThreadWithPID(pid, false);
}

void ProcessWindow::CreateProfileForSelectedProcess()
{
	DWORD pid = GetSelectedPID();
	auto path = GetProcessPath(pid);
	if (!path.empty())
	{
		Profile* pf = pfman->CreateProfile(pid);
        pfman->SaveProfiles();
		RefreshThread(ListView_GetSelectionMark(hlProcess));
	}
}

void ProcessWindow::DeleteProfileForSelectedProcess()
{
	DWORD pid = GetSelectedPID();
	auto path = GetProcessPath(pid);
	if (!path.empty())
	{
		pfman->DeleteProfile(path);
		RefreshThread(ListView_GetSelectionMark(hlProcess));
	}
}

void ProcessWindow::RefreshThread(int index)
{
	LVITEM item = {};
	item.mask = LVIF_PARAM;
	item.iItem = index;
	ListView_GetItem(hlProcess, &item);
	DWORD pid = item.lParam;
	bool isAttached = man->GetHostPipe(pid) != NULL;
	RefreshThreadWithPID(pid, isAttached);
}

void ProcessWindow::RefreshThreadWithPID(DWORD pid, bool isAttached)
{
	EnableWindow(hbDetach, isAttached);
	EnableWindow(hbAttach, !isAttached);
	auto path = GetProcessPath(pid);
	bool hasProfile = !path.empty() && pfman->HasProfile(path);
	EnableWindow(hbAddProfile, isAttached && !hasProfile);
	EnableWindow(hbRemoveProfile, hasProfile);
	if (pid == GetCurrentProcessId())
		EnableWindow(hbAttach, FALSE);
}

DWORD ProcessWindow::GetSelectedPID()
{
	LVITEM item = {};
	item.mask = LVIF_PARAM;
	item.iItem = ListView_GetSelectionMark(hlProcess);
	ListView_GetItem(hlProcess, &item);
	return item.lParam;
}

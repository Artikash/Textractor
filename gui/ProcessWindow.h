#pragma once
#include "ITH.h"

class ProcessWindow
{
public:
	ProcessWindow(HWND hDialog);
	void InitProcessDlg();
	void RefreshProcess();
	void AttachProcess();
	void DetachProcess();
	void AddCurrentToProfile();
	void RemoveCurrentFromProfile();
	void RefreshThread(int index);
private:
	void RefreshThreadWithPID(DWORD pid, bool isAttached);
	DWORD GetSelectedPID();
	HWND hDlg;
	HWND hlProcess;
	HWND hbRefresh,hbAttach,hbDetach,hbAddProfile,hbRemoveProfile;
	HWND heOutput;
};

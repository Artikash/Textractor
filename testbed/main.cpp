#include "common.h"
#include "defs.h"
#include "resource.h"

wchar_t buffer[1000] = {};
std::array<int, 10> vars = {};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int)
{
	LoadLibraryW(ITH_DLL);

	ShowWindow(CreateDialogParamW(hInstance, MAKEINTRESOURCEW(IDD_DIALOG1), NULL, [](HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) -> INT_PTR
	{
		switch (uMsg)
		{
		case WM_CLOSE:
		{
			DestroyWindow(hWnd);
		}
		return TRUE;
		case WM_DESTROY:
		{
			PostQuitMessage(0);
		}
		return TRUE;
		case WM_COMMAND:
		{
			if (HIWORD(wParam) == EN_CHANGE)
			{
				GetWindowTextW((HWND)lParam, buffer, std::size(buffer));
				try { vars.at(LOWORD(wParam) - IDC_EDIT1) = std::stoi(buffer); }
				catch (...) {}
			}
		}
		break;
		}
		return FALSE;
	}, 0), SW_SHOW);

	std::thread([] { while (true) lstrlenW(L"こんにちは"); }).detach();

	MSG msg;
	while (GetMessageW(&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}
	return 0;
}

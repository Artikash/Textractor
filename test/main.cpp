#include "common.h"
#include "defs.h"
#include "resource.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <QApplication>

wchar_t buffer[1000] = {};
std::array<int, 10> vars = {};

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int _)
{
	QApplication a(_ = 0, DUMMY);
	static std::vector<AutoHandle<Functor<(void(__stdcall *)(void*))FreeLibrary>>> extensions;
	for (auto file : std::filesystem::directory_iterator(std::filesystem::current_path()))
		if (file.path().extension() == L".dll"
			&& (std::stringstream() << std::ifstream(file.path(), std::ios::binary).rdbuf()).str().find("OnNewSentence") != std::string::npos)
			extensions.emplace_back(LoadLibraryW(file.path().c_str()));

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
				if (vars.at(1)) extensions.clear();
			}
		}
		break;
		}
		return FALSE;
	}, 0), SW_SHOW);

	std::thread([] { while (true) Sleep(vars.at(0)), lstrlenW(L"こんにちは\n　(Hello)"); }).detach();

	STARTUPINFOW info = { sizeof(info) };
	wchar_t commandLine[] = { L"Textractor -p\"Test.exe\"" };
	CreateProcessW(NULL, commandLine, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &info, DUMMY);

	MSG msg;
	while (GetMessageW(&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}
	return 0;
}

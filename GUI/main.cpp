#include "mainwindow.h"
#include <QApplication>

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* exception)
{
	std::wstring errorMsg(L"");
	errorMsg += L"Error code: " + std::to_wstring(exception->ExceptionRecord->ExceptionCode);
	errorMsg += L"\r\nError address: " + std::to_wstring((DWORD)exception->ExceptionRecord->ExceptionAddress);
	errorMsg += L"\r\nAdditional info: " + std::to_wstring(exception->ExceptionRecord->ExceptionInformation[1]);
	MessageBoxW(NULL, errorMsg.c_str(), L"NextHooker ERROR", MB_ICONERROR);
	return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char *argv[])
{
	AddVectoredExceptionHandler(1, ExceptionHandler);
	QApplication a(argc, argv);
	MainWindow w;
	w.show();

	return a.exec();
}

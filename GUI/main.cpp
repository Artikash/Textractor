#include "mainwindow.h"
#include <sstream>
#include <QApplication>

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* exception)
{
	MEMORY_BASIC_INFORMATION info = {};
	VirtualQuery(exception->ExceptionRecord->ExceptionAddress, &info, sizeof(info));
	wchar_t moduleName[MAX_PATH] = {};
	GetModuleFileNameW((HMODULE)info.AllocationBase, moduleName, MAX_PATH);

	std::wstringstream errorMsg;
	errorMsg << 
		std::uppercase << std::hex <<
		L"Error code: " << exception->ExceptionRecord->ExceptionCode << std::endl <<
		L"Error address: " << (DWORD)exception->ExceptionRecord->ExceptionAddress << std::endl <<
		L"Error in module: " << moduleName << std::endl <<
		L"Additional info: " << exception->ExceptionRecord->ExceptionInformation[1];
	MessageBoxW(NULL, errorMsg.str().c_str(), L"NextHooker ERROR", MB_ICONERROR);
	return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char *argv[])
{
	SetUnhandledExceptionFilter(ExceptionHandler);
	QApplication a(argc, argv);
	MainWindow w;
	w.show();

	return a.exec();
}

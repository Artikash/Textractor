#include "mainwindow.h"
#include <sstream>
#include <QApplication>

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* exception)
{
	std::wstringstream errorMsg;
	errorMsg << std::uppercase << std::hex;
	errorMsg << L"Error code: " << exception->ExceptionRecord->ExceptionCode << std::endl;
	errorMsg << L"Error address: " << (DWORD)exception->ExceptionRecord->ExceptionAddress << std::endl;
	MEMORY_BASIC_INFORMATION info = {};
	VirtualQuery(exception->ExceptionRecord->ExceptionAddress, &info, sizeof(info));
	wchar_t name[MAX_PATH] = {};
	GetModuleFileNameW((HMODULE)info.AllocationBase, name, MAX_PATH);
	errorMsg << L"Error in module: " << name << std::endl;
	errorMsg << L"Additional info: " << exception->ExceptionRecord->ExceptionInformation[1];
	MessageBoxW(NULL, errorMsg.str().c_str(), L"NextHooker ERROR", MB_ICONERROR);
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

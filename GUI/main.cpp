#include "mainwindow.h"
#include <sstream>
#include <QApplication>

namespace
{
	char* GetCppExceptionInfo(EXCEPTION_POINTERS* exception)
	{
		// See https://blogs.msdn.microsoft.com/oldnewthing/20100730-00/?p=13273
		// Not very reliable so use __try
		__try { return ((char****)exception->ExceptionRecord->ExceptionInformation[2])[3][1][1] + 8; }
		__except (EXCEPTION_EXECUTE_HANDLER) { return "Could not find"; }
	}

	LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* exception)
	{
		MEMORY_BASIC_INFORMATION info = {};
		VirtualQuery(exception->ExceptionRecord->ExceptionAddress, &info, sizeof(info));
		wchar_t moduleName[MAX_PATH] = {};
		GetModuleFileNameW((HMODULE)info.AllocationBase, moduleName, MAX_PATH);

		std::wstringstream errorMsg;
		errorMsg << std::uppercase << std::hex <<
			L"Error code: " << exception->ExceptionRecord->ExceptionCode << std::endl <<
			L"Error address: " << (uint64_t)exception->ExceptionRecord->ExceptionAddress << std::endl <<
			L"Error in module: " << moduleName << std::endl;

		if (exception->ExceptionRecord->ExceptionCode == 0xE06D7363)
			errorMsg << L"Additional info: " << GetCppExceptionInfo(exception) << std::endl;

		for (int i = 0; i < exception->ExceptionRecord->NumberParameters; ++i)
			errorMsg << L"Additional info: " << exception->ExceptionRecord->ExceptionInformation[i] << std::endl;

		MessageBoxW(NULL, errorMsg.str().c_str(), L"Textractor ERROR", MB_ICONERROR);

		return EXCEPTION_CONTINUE_SEARCH;
	}
}

int main(int argc, char *argv[])
{
	SetUnhandledExceptionFilter(ExceptionHandler);
	QApplication a(argc, argv);
	MainWindow w;
	w.show();
	return a.exec();
}

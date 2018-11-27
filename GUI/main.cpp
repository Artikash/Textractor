#include "mainwindow.h"
#include "host/util.h"
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

	thread_local std::wstring lastError = L"Unknown error";

	LONG WINAPI ExceptionLogger(EXCEPTION_POINTERS* exception)
	{
		MEMORY_BASIC_INFORMATION info = {};
		VirtualQuery(exception->ExceptionRecord->ExceptionAddress, &info, sizeof(info));

		std::wstringstream errorMsg;
		errorMsg << std::uppercase << std::hex <<
			L"Error code: " << exception->ExceptionRecord->ExceptionCode << std::endl <<
			L"Error address: " << exception->ExceptionRecord->ExceptionAddress << std::endl <<
			L"Error in module: " << Util::GetModuleFileName((HMODULE)info.AllocationBase).value_or(L"Could not find") << std::endl <<
			L"Additional info: " << info.AllocationBase << std::endl;

		if (exception->ExceptionRecord->ExceptionCode == 0xE06D7363)
		{
			errorMsg << L"Additional info: " << GetCppExceptionInfo(exception) << std::endl;
			if (errorMsg.str().find(L"exception")) errorMsg << ((std::exception*)exception->ExceptionRecord->ExceptionInformation[1])->what();
		}

		for (int i = 0; i < exception->ExceptionRecord->NumberParameters; ++i)
			errorMsg << L"Additional info: " << exception->ExceptionRecord->ExceptionInformation[i] << std::endl;

		lastError = errorMsg.str();
		return EXCEPTION_CONTINUE_SEARCH;
	}

	__declspec(noreturn) void Terminate()
	{
		MessageBoxW(NULL, lastError.c_str(), L"Textractor ERROR", MB_ICONERROR);
		std::abort();
	}

	thread_local auto _ = [] { return std::set_terminate(Terminate); }();
}

int main(int argc, char *argv[])
{
	AddVectoredExceptionHandler(FALSE, ExceptionLogger);
	SetUnhandledExceptionFilter([](auto) -> LONG { Terminate(); });

	std::wstring exe = Util::GetModuleFileName().value();
	while (exe.back() != L'\\') exe.pop_back();
	SetCurrentDirectoryW(exe.c_str());

	QApplication a(argc, argv);
	MainWindow w;
	w.show();
	return a.exec();
}

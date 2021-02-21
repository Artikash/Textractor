#include "module.h"
#include <sstream>

namespace
{
	char* GetCppExceptionInfo(EXCEPTION_POINTERS* exception)
	{
		// See https://blogs.msdn.microsoft.com/oldnewthing/20100730-00/?p=13273
		// Not very reliable so use __try
		__try { return ((char****)exception->ExceptionRecord->ExceptionInformation[2])[3][1][1] + 8; }
		__except (EXCEPTION_EXECUTE_HANDLER) { return "Could not find"; }
	}

	const char* GetCppExceptionMessage(EXCEPTION_POINTERS* exception)
	{
		__try { return ((std::exception*)exception->ExceptionRecord->ExceptionInformation[1])->what(); }
		__except (EXCEPTION_EXECUTE_HANDLER) { return "Could not find"; }
	}

	thread_local std::wstring lastError = L"Unknown error";

	__declspec(noreturn) void Terminate()
	{
		WaitForSingleObject(CreateThread(nullptr, 0, [](void* lastError) -> DWORD
		{
			MessageBoxW(NULL, (wchar_t*)lastError, L"Textractor ERROR", MB_ICONERROR); // might fail to display if called in main thread and exception was in main event loop
			abort();
		}, lastError.data(), 0, nullptr), INFINITE);
	}

	LONG WINAPI ExceptionLogger(EXCEPTION_POINTERS* exception)
	{
		thread_local static auto _ = set_terminate(Terminate);

		MEMORY_BASIC_INFORMATION info = {};
		VirtualQuery(exception->ExceptionRecord->ExceptionAddress, &info, sizeof(info));

		std::wstringstream errorMsg;
		errorMsg << std::uppercase << std::hex <<
			L"Error code: " << exception->ExceptionRecord->ExceptionCode << std::endl <<
			L"Error address: " << exception->ExceptionRecord->ExceptionAddress << std::endl <<
			L"Error in module: " << GetModuleFilename((HMODULE)info.AllocationBase).value_or(L"Could not find") << std::endl <<
			L"Additional info: " << info.AllocationBase << std::endl;

		if (exception->ExceptionRecord->ExceptionCode == 0xE06D7363)
		{
			if (char* info = GetCppExceptionInfo(exception)) errorMsg << L"Additional info: " << info << std::endl;
			if (const char* info = GetCppExceptionMessage(exception)) errorMsg << L"Additional info: " << info << std::endl;
		}

		for (int i = 0; i < exception->ExceptionRecord->NumberParameters; ++i)
			errorMsg << L"Additional info: " << exception->ExceptionRecord->ExceptionInformation[i] << std::endl;

		lastError = errorMsg.str();
		return EXCEPTION_CONTINUE_SEARCH;
	}

	auto _ = (AddVectoredExceptionHandler(FALSE, ExceptionLogger), SetUnhandledExceptionFilter([](auto) -> LONG { Terminate(); }));
}

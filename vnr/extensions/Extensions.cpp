#include <Windows.h>
#include <map>

typedef void(*ExtensionFunction)(LPCWSTR, DWORD64);

std::map<DWORD, ExtensionFunction> extensionFunctions;

void LoadExtensions()
{
	wchar_t path[MAX_PATH];
	wchar_t* end = path + GetModuleFileNameW(nullptr, path, MAX_PATH);
	while (*(--end) != L'\\');
	*(end + 1) = L'*';
	*(end + 2) = L'\0';
	WIN32_FIND_DATAW fileData;
	HANDLE file = FindFirstFileW(path, &fileData);
	do
	{
		if (fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
		}
		else
		{
			if (wcsstr(fileData.cFileName, L"_nexthooker_extension.dll"))
			{ 
				extensionFunctions[wcstoul(fileData.cFileName, nullptr, 10)] = (ExtensionFunction)GetProcAddress(LoadLibraryW(fileData.cFileName), "OnSentence");
			}
		}
	} while (FindNextFileW(file, &fileData) != 0);
}

void DispatchSentenceToExtensions(LPCWSTR sentence, DWORD64 info)
{
	for (auto extension : extensionFunctions)
	{
		extension.second(sentence, info);
	}
}
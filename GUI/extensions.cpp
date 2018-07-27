#include "extensions.h"
#include <map>

std::map<int, ExtensionFunction> extensions;

std::map<int, std::wstring> LoadExtensions()
{
	std::map<int, std::wstring> extensionNames;
	wchar_t path[MAX_PATH];
	wchar_t* end = path + GetModuleFileNameW(nullptr, path, MAX_PATH);
	while (*(--end) != L'\\');
	*(end + 1) = L'*';
	*(end + 2) = L'\0';
	WIN32_FIND_DATAW fileData;
	HANDLE file = FindFirstFileW(path, &fileData);
	do
		if (!(fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			if (wcsstr(fileData.cFileName, L"_nexthooker_extension.dll"))
				if (GetProcAddress(LoadLibraryW(fileData.cFileName), "OnNewSentence"))
				{
					extensions[std::wcstol(fileData.cFileName, nullptr, 10)] = (ExtensionFunction)GetProcAddress(LoadLibraryW(fileData.cFileName), "OnNewSentence");
					extensionNames[std::wcstol(fileData.cFileName, nullptr, 10)] = fileData.cFileName;
				}
	while (FindNextFileW(file, &fileData) != 0);
	return extensionNames;
}

std::wstring DispatchSentenceToExtensions(std::wstring sentence, std::unordered_map<std::string, int> miscInfo)
{
	for (auto extension : extensions) sentence = extension.second(sentence, miscInfo);
	return sentence;
}

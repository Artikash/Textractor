#include "extensions.h"
#include <map>
#include <QDir>

std::map<int, ExtensionFunction> extensions;

std::map<int, QString> LoadExtensions()
{
	extensions = std::map<int, ExtensionFunction>();
	std::map<int, QString> extensionNames;
	wchar_t path[MAX_PATH] = {};
	(QDir::currentPath() + "/*_nexthooker_extension.dll").toWCharArray(path);
	WIN32_FIND_DATAW fileData;
	HANDLE file = FindFirstFileW(path, &fileData);
	do
		if (GetProcAddress(GetModuleHandleW(fileData.cFileName), "OnNewSentence") ||
			GetProcAddress(LoadLibraryW(fileData.cFileName), "OnNewSentence")
		)
		{
			extensions[std::wcstol(fileData.cFileName, nullptr, 10)] = (ExtensionFunction)GetProcAddress(GetModuleHandleW(fileData.cFileName), "OnNewSentence");
			QString name = QString::fromWCharArray(fileData.cFileName);
			name.chop(sizeof("_nexthooker_extension.dll") - 1);
			name.remove(0, name.split("_")[0].length() + 1);
			extensionNames[std::wcstol(fileData.cFileName, nullptr, 10)] = name;
		}
	while (FindNextFileW(file, &fileData) != 0);
	return extensionNames;
}

std::wstring DispatchSentenceToExtensions(std::wstring sentence, std::unordered_map<std::string, int> miscInfo)
{
	for (auto extension : extensions)
		extension.second(sentence, miscInfo);
	return sentence;
}

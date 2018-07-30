#include "extensions.h"
#include <map>
#include <QDir>

std::map<int, ExtensionFunction> extensions;
int processing;

std::map<int, QString> LoadExtensions()
{
	std::map<int, ExtensionFunction> newExtensions;
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
			newExtensions[std::wcstol(fileData.cFileName, nullptr, 10)] = (ExtensionFunction)GetProcAddress(GetModuleHandleW(fileData.cFileName), "OnNewSentence");
			QString name = QString::fromWCharArray(fileData.cFileName);
			name.chop(sizeof("_nexthooker_extension.dll") - 1);
			name.remove(0, name.split("_")[0].length() + 1);
			extensionNames[std::wcstol(fileData.cFileName, nullptr, 10)] = name;
		}
	while (FindNextFileW(file, &fileData) != 0);
	while (processing) Sleep(10);
	processing = -1;
	extensions = newExtensions;
	processing = 0;
	return extensionNames;
}

std::wstring DispatchSentenceToExtensions(std::wstring sentence, std::unordered_map<std::string, int> miscInfo)
{
	while (processing < 0) Sleep(10);
	processing++;
	wchar_t* sentenceBuffer = new wchar_t[sentence.size() + 1];
	wcscpy(sentenceBuffer, sentence.c_str());
	InfoForExtension* miscInfoLinkedList = new InfoForExtension;
	InfoForExtension* miscInfoTraverser = miscInfoLinkedList;
	for (auto i : miscInfo)
	{
		miscInfoTraverser->propertyName = new char[i.first.size() + 1];
		strcpy(miscInfoTraverser->propertyName, i.first.c_str());
		miscInfoTraverser->propertyValue = i.second;
		miscInfoTraverser->nextProperty = new InfoForExtension;
		miscInfoTraverser = miscInfoTraverser->nextProperty;
	}
	miscInfoTraverser->propertyName = new char[sizeof("END")];
	strcpy(miscInfoTraverser->propertyName, "END");
	miscInfoTraverser->nextProperty = nullptr;
	for (auto i : extensions)
		sentenceBuffer = i.second(sentenceBuffer, miscInfoLinkedList);
	miscInfoTraverser = miscInfoLinkedList;
	while (miscInfoTraverser != nullptr)
	{
		InfoForExtension* nextNode = miscInfoTraverser->nextProperty;
		delete[] miscInfoTraverser->propertyName;
		delete miscInfoTraverser;
		miscInfoTraverser = nextNode;
	}
	std::wstring newSentence = std::wstring(sentenceBuffer);
	delete[] sentenceBuffer;
	processing--;
	return newSentence;
}

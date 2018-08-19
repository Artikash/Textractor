#include "extensions.h"
#include <map>
#include <QDir>

std::map<int, ExtensionFunction> extensions;
int processing;

std::map<int, QString> LoadExtensions()
{
	std::map<int, ExtensionFunction> newExtensions;
	std::map<int, QString> extensionNames;
	QStringList files = QDir().entryList();
	for (auto file : files)
		if (file.endsWith("_nexthooker_extension.dll"))
			if (GetProcAddress(GetModuleHandleW(file.toStdWString().c_str()), "OnNewSentence") ||
				GetProcAddress(LoadLibraryW(file.toStdWString().c_str()), "OnNewSentence"))
			{
				QString extensionNumber = file.split("_")[0];
				newExtensions[extensionNumber.toInt()] = (ExtensionFunction)GetProcAddress(GetModuleHandleW(file.toStdWString().c_str()), "OnNewSentence");
				file.chop(sizeof("_nexthooker_extension.dll") - 1);
				file.remove(0, extensionNumber.length() + 1);
				extensionNames[extensionNumber.toInt()] = file;
			}
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
	wchar_t* sentenceOrigBuffer = (wchar_t*)malloc((sentence.size() + 1) * sizeof(wchar_t));
	wcscpy(sentenceOrigBuffer, sentence.c_str());
	const wchar_t* sentenceBuffer = sentenceOrigBuffer;
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
	{
		const wchar_t* prev = sentenceBuffer;
		sentenceBuffer = i.second(sentenceBuffer, miscInfoLinkedList);
		if (sentenceBuffer == nullptr) sentence = prev;
		if (sentenceBuffer != prev) free((void*)prev);
	}
	miscInfoTraverser = miscInfoLinkedList;
	while (miscInfoTraverser != nullptr)
	{
		InfoForExtension* nextNode = miscInfoTraverser->nextProperty;
		delete[] miscInfoTraverser->propertyName;
		delete miscInfoTraverser;
		miscInfoTraverser = nextNode;
	}
	std::wstring newSentence = std::wstring(sentenceBuffer);
	free((void*)sentenceBuffer);
	processing--;
	return newSentence;
}

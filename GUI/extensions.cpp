#include "extensions.h"
#include <shared_mutex>
#include <map>
#include <QDir>

std::shared_mutex extenMutex;
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
	extenMutex.lock();
	extensions = newExtensions;
	extenMutex.unlock();
	return extensionNames;
}

std::wstring DispatchSentenceToExtensions(std::wstring sentence, std::unordered_map<std::string, int> miscInfo)
{
	wchar_t* sentenceBuffer = (wchar_t*)malloc((sentence.size() + 1) * sizeof(wchar_t));
	wcscpy(sentenceBuffer, sentence.c_str());
	InfoForExtension* miscInfoLinkedList = new InfoForExtension;
	InfoForExtension* miscInfoTraverser = miscInfoLinkedList;
	for (auto& i : miscInfo) miscInfoTraverser = miscInfoTraverser->nextProperty = new InfoForExtension{ i.first.c_str(), i.second, new InfoForExtension };
	extenMutex.lock_shared();
	for (auto i : extensions)
	{
		wchar_t* prev = sentenceBuffer;
		sentenceBuffer = i.second(sentenceBuffer, miscInfoLinkedList);
		if (sentenceBuffer != prev) free((void*)prev);
	}
	extenMutex.unlock_shared();
	delete miscInfoLinkedList;
	std::wstring newSentence = std::wstring(sentenceBuffer);
	free((void*)sentenceBuffer);
	return newSentence;
}

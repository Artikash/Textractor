#include "extensions.h"
#include <shared_mutex>
#include <QDir>

std::shared_mutex extenMutex;
std::map<int, ExtensionFunction> extensions;

std::map<int, QString> LoadExtensions()
{
	std::map<int, ExtensionFunction> newExtensions;
	std::map<int, QString> extensionNames;
	QStringList files = QDir().entryList();
	for (auto file : files)
		if (file.split("_").size() > 1 && file.split("_")[0].toInt() && file.endsWith(".dll"))
			if (GetProcAddress(GetModuleHandleW(file.toStdWString().c_str()), "OnNewSentence") ||
				GetProcAddress(LoadLibraryW(file.toStdWString().c_str()), "OnNewSentence"))
			{
				int extensionNumber = file.split("_")[0].toInt();
				newExtensions[extensionNumber] = (ExtensionFunction)GetProcAddress(GetModuleHandleW(file.toStdWString().c_str()), "OnNewSentence");
				file.chop(sizeof("dll"));
				file.remove(0, file.indexOf("_") + 1);
				extensionNames[extensionNumber] = file;
			}
	std::unique_lock<std::shared_mutex> extenLock(extenMutex);
	extensions = newExtensions;
	return extensionNames;
}

bool DispatchSentenceToExtensions(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo)
{
	bool success = true;
	wchar_t* sentenceBuffer = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (sentence.size() + 1) * sizeof(wchar_t));
	wcscpy_s(sentenceBuffer, sentence.size() + 1, sentence.c_str());
	InfoForExtension* miscInfoLinkedList = new InfoForExtension;
	InfoForExtension* miscInfoTraverser = miscInfoLinkedList;
	for (auto& i : miscInfo) miscInfoTraverser = miscInfoTraverser->nextProperty = new InfoForExtension{ i.first.c_str(), i.second, nullptr };
	std::shared_lock<std::shared_mutex> extenLock(extenMutex);
	for (auto i : extensions)
	{
		wchar_t* nextBuffer = i.second(sentenceBuffer, miscInfoLinkedList);
		if (nextBuffer == nullptr) { success = false; break; }
		if (nextBuffer != sentenceBuffer) HeapFree(GetProcessHeap(), 0, sentenceBuffer);
		sentenceBuffer = nextBuffer;
	}
	sentence = std::wstring(sentenceBuffer);
	HeapFree(GetProcessHeap(), 0, sentenceBuffer);
	delete miscInfoLinkedList;
	return success;
}

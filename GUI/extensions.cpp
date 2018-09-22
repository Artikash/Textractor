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
				extensionNames[extensionNumber] = file.split("_")[1];
			}
	extenMutex.lock();
	extensions = newExtensions;
	extenMutex.unlock();
	return extensionNames;
}

bool DispatchSentenceToExtensions(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo)
{
	wchar_t* sentenceBuffer = (wchar_t*)malloc((sentence.size() + 1) * sizeof(wchar_t));
	wcscpy_s(sentenceBuffer, sentence.size() + 1, sentence.c_str());
	InfoForExtension* miscInfoLinkedList = new InfoForExtension;
	InfoForExtension* miscInfoTraverser = miscInfoLinkedList;
	for (auto& i : miscInfo) miscInfoTraverser = miscInfoTraverser->nextProperty = new InfoForExtension{ i.first.c_str(), i.second, nullptr };
	extenMutex.lock_shared();
	try
	{
		for (auto i : extensions)
		{
			wchar_t* prev = sentenceBuffer;
			sentenceBuffer = i.second(sentenceBuffer, miscInfoLinkedList);
			if (sentenceBuffer != prev) free((void*)prev);
		}
	}
	catch (...) { sentenceBuffer[0] = 0; }
	extenMutex.unlock_shared();
	delete miscInfoLinkedList;
	sentence = std::wstring(sentenceBuffer);
	free((void*)sentenceBuffer);
	return sentence.size() > 0;
}

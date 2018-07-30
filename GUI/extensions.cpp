#include "extensions.h"
#include <map>
#include <QDir>
#include <thread>
#include <mutex>

std::map<int, ExtensionFunction> extensions;
static std::mutex MutexGuard;

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

    {
        std::lock_guard<std::mutex> lock(MutexGuard);
	    extensions = newExtensions;
    }

	return extensionNames;
}

std::wstring DispatchSentenceToExtensions(std::wstring sentence, std::unordered_map<std::string, int> miscInfo)
{
    std::lock_guard<std::mutex> lock(MutexGuard);

    const wchar_t* sentenceOriginalBuff = sentence.c_str();
    const wchar_t* sentenceBuffer = sentenceOriginalBuff;

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

	for (auto i : extensions) {
        const wchar_t* prev = sentenceBuffer;
		sentenceBuffer = i.second(sentenceBuffer, miscInfoLinkedList);

        if (sentenceBuffer == nullptr) sentence = prev;
        else if (sentenceBuffer != prev && sentenceBuffer != sentenceOriginalBuff) {
            //TODO: Plugin should define own free function?
            free(static_cast<void*>(const_cast<wchar_t*>(prev)));
        }
    }

	miscInfoTraverser = miscInfoLinkedList;
	while (miscInfoTraverser != nullptr)
	{
		InfoForExtension* nextNode = miscInfoTraverser->nextProperty;
		delete[] miscInfoTraverser->propertyName;
		delete miscInfoTraverser;
		miscInfoTraverser = nextNode;
	}

    if (sentenceBuffer != sentenceOriginalBuff) {
	    sentence = std::wstring(sentenceBuffer);
        //TODO: Plugin should define own free function?
        free(static_cast<void*>(const_cast<wchar_t*>(sentenceBuffer)));
    }

	return sentence;
}

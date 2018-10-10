#include "extensions.h"
#include <shared_mutex>
#include <QDir>

std::optional<Extension> LoadExtension(QString file)
{
	// Extension file format: {NUMBER}_{NAME}.dll and exports "OnNewSentence"
	QRegularExpressionMatch parsedFile = QRegularExpression("^(\\d+)_(.+).dll$").match(file);
	if (!parsedFile.hasMatch()) return {};
	HMODULE module = GetModuleHandleW(file.toStdWString().c_str());
	if (!module) module = LoadLibraryW(file.toStdWString().c_str());
	if (!module) return {};
	FARPROC callback = GetProcAddress(module, "OnNewSentence");
	if (!callback) return {};
	return Extension{ parsedFile.captured(1).toInt(), parsedFile.captured(2), (wchar_t*(*)(const wchar_t*, const InfoForExtension*))callback };
}

std::shared_mutex extenMutex;
std::set<Extension> extensions;

std::set<Extension> LoadExtensions()
{
	std::set<Extension> newExtensions;
	QStringList files = QDir().entryList();
	for (auto file : files)
		if (auto extension = LoadExtension(file)) newExtensions.insert(extension.value());
	std::unique_lock<std::shared_mutex> extenLock(extenMutex);
	return extensions = newExtensions;
}

bool DispatchSentenceToExtensions(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo)
{
	bool success = true;
	wchar_t* sentenceBuffer = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (sentence.size() + 1) * sizeof(wchar_t));
	wcscpy_s(sentenceBuffer, sentence.size() + 1, sentence.c_str());

	InfoForExtension miscInfoLinkedList{ "", 0, nullptr };
	InfoForExtension* miscInfoTraverser = &miscInfoLinkedList;
	for (auto& i : miscInfo) miscInfoTraverser = miscInfoTraverser->next = new InfoForExtension{ i.first.c_str(), i.second, nullptr };

	std::shared_lock<std::shared_mutex> extenLock(extenMutex);
	for (auto extension : extensions)
	{
		wchar_t* nextBuffer = extension.callback(sentenceBuffer, &miscInfoLinkedList);
		if (nextBuffer == nullptr) { success = false; break; }
		if (nextBuffer != sentenceBuffer) HeapFree(GetProcessHeap(), 0, sentenceBuffer);
		sentenceBuffer = nextBuffer;
	}
	sentence = std::wstring(sentenceBuffer);

	HeapFree(GetProcessHeap(), 0, sentenceBuffer);
	return success;
}

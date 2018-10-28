#include "extensions.h"

static std::optional<Extension> LoadExtension(QString extenName)
{
	// Extension is dll and exports "OnNewSentence"
	HMODULE module = GetModuleHandleW(extenName.toStdWString().c_str());
	if (!module) module = LoadLibraryW(extenName.toStdWString().c_str());
	if (!module) return {};
	FARPROC callback = GetProcAddress(module, "OnNewSentence");
	if (!callback) return {};
	return Extension{ extenName, (wchar_t*(*)(const wchar_t*, const InfoForExtension*))callback };
}

void Extension::Load(QString extenName)
{
	std::unique_lock<std::shared_mutex> extenLock(extenMutex);
	if (auto extension = LoadExtension(extenName)) extensions.push_back(extension.value());
}

void Extension::SendToBack(QString extenName)
{
	std::unique_lock<std::shared_mutex> extenLock(extenMutex);
	Extension* extenIter = std::find_if(extensions.begin(), extensions.end(), [&](Extension extension) { return extension.name == extenName; });
	Extension extension = *extenIter;
	extensions.erase(extenIter);
	extensions.push_back(extension);
}

void Extension::Unload(QString extenName)
{
	std::unique_lock<std::shared_mutex> extenLock(extenMutex);
	extensions.erase(std::find_if(extensions.begin(), extensions.end(), [&](Extension extension) { return extension.name == extenName; }));
	FreeLibrary(GetModuleHandleW(extenName.toStdWString().c_str()));
}

QVector<QString> Extension::GetNames()
{
	QVector<QString> ret;
	for (auto extension : extensions) ret.push_back(extension.name);
	return ret;
}

bool Extension::DispatchSentence(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo)
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

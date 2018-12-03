#include "../extension.h"
#include "window.h"
#include <QTimer>

Window* w = nullptr;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		QTimer::singleShot(0, [] { (w = new Window)->show(); });
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		if (lpReserved == NULL) delete w; // https://blogs.msdn.microsoft.com/oldnewthing/20120105-00/?p=8683
	}
	break;
	}
	return TRUE;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (w == nullptr) return false;
	std::lock_guard l(w->m);
	
	static std::unordered_map<int64_t, std::wstring> queuedWritesByHandle;
	int64_t textHandle = sentenceInfo["text handle"];
	for (auto linkedHandle : w->linkedTextHandles[textHandle]) queuedWritesByHandle[linkedHandle] += L"\r\n" + sentence;
	if (queuedWritesByHandle[textHandle].empty()) return false;
	sentence += queuedWritesByHandle[textHandle];
	queuedWritesByHandle[textHandle].clear();
	return true;
}

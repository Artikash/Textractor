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
		if (lpReserved == NULL && w != nullptr) delete w; // https://blogs.msdn.microsoft.com/oldnewthing/20120105-00/?p=8683
	}
	break;
	}
	return TRUE;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (w == nullptr || sentenceInfo["hook address"] == -1) return false;
	std::lock_guard l(w->m);
	sentence = std::regex_replace(sentence, w->regex, L"");
	return true;
}
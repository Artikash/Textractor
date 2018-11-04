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
		delete w;
	}
	break;
	}
	return TRUE;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (w == nullptr) return false;
	std::lock_guard l(w->m);
	sentence = std::regex_replace(sentence, w->regex, L"");
	return true;
}
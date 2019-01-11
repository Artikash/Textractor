#include "extension.h"

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["hook address"] == -1) return false;
	sentence += L"\n";
	return true;
}

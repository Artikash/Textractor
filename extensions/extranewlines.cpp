#include "extensions.h"

bool ProcessSentence(std::wstring& sentence, const InfoForExtension* miscInfo)
{
	if (GetProperty("hook address", miscInfo) == -1) return false;
	sentence += L"\r\n";
	return true;
}
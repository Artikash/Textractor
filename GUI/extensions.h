#ifndef EXTENSIONS_H
#define EXTENSIONS_H

#include "qtcommon.h"
#include <map>

std::map<int, QString> LoadExtensions();
bool DispatchSentenceToExtensions(std::wstring& sentence, std::unordered_map<std::string, int> miscInfo);
struct InfoForExtension
{
	~InfoForExtension() { if (nextProperty) delete nextProperty; };
	const char* propertyName = "";
	int propertyValue = 0;
	InfoForExtension* nextProperty = nullptr;
};
typedef wchar_t*(*ExtensionFunction)(const wchar_t*, const InfoForExtension*);

#endif // EXTENSIONS_H

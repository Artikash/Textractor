#ifndef EXTENSIONS_H
#define EXTENSIONS_H

#include <Windows.h>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <QComboBox>

std::map<int, QString> LoadExtensions();
std::wstring DispatchSentenceToExtensions(std::wstring sentence, std::unordered_map<std::string, int> miscInfo);
struct InfoForExtension
{
	~InfoForExtension() { if (nextProperty) delete nextProperty; };
	const char* propertyName = "";
	int propertyValue = 0;
	InfoForExtension* nextProperty = nullptr;
};
typedef wchar_t*(*ExtensionFunction)(const wchar_t*, const InfoForExtension*);

#endif // EXTENSIONS_H

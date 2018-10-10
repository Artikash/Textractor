#ifndef EXTENSIONS_H
#define EXTENSIONS_H

#include "qtcommon.h"
#include <set>

struct InfoForExtension
{
	const char* name;
	int64_t value;
	InfoForExtension* next;
	~InfoForExtension() { if (next) delete next; };
};

struct Extension
{
	int number;
	QString name;
	wchar_t*(*callback)(const wchar_t*, const InfoForExtension*);
	bool operator<(const Extension& other) const { return number < other.number; }
};

std::set<Extension> LoadExtensions();
bool DispatchSentenceToExtensions(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo);

#endif // EXTENSIONS_H

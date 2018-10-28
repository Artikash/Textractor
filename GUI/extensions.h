#ifndef EXTENSIONS_H
#define EXTENSIONS_H

#include "qtcommon.h"
#include <shared_mutex>

struct InfoForExtension
{
	const char* name;
	int64_t value;
	InfoForExtension* next;
	~InfoForExtension() { if (next) delete next; };
};

class Extension
{
public:
	static bool DispatchSentence(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo);
	static void Load(QString extenName);
	static void SendToBack(QString extenName);
	static void Unload(QString extenName);
	static QVector<QString> GetNames();

	QString name;
	wchar_t* (*callback)(const wchar_t*, const InfoForExtension*);

private:
	inline static std::shared_mutex extenMutex;
	inline static QVector<Extension> extensions;
};

#endif // EXTENSIONS_H

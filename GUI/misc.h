#ifndef MISC_H
#define MISC_H

#include "qtcommon.h"
#include "types.h"

class QAutoFile
{
public:
	QAutoFile(QString name, QIODevice::OpenMode mode) : f(name) { f.open(mode); }
	QFile* operator->() { return &f; }
private:
	QFile f;
};

QMultiHash<QString, DWORD> GetAllProcesses();
std::optional<HookParam> ParseCode(QString HCode);
QString GenerateCode(HookParam hp, DWORD processId);

#endif // MISC_H

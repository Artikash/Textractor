#pragma once

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

std::wstring S(const QString& S);
QString S(const std::wstring& S);
std::optional<HookParam> ParseCode(QString HCode);
QString GenerateCode(HookParam hp, DWORD processId);

#pragma once

#include "qtcommon.h"
#include "types.h"

class QAutoFile
{
public:
	QAutoFile(const QString& name, QIODevice::OpenMode mode) : f(name) { f.open(mode); }
	QFile* operator->() { return &f; }

private:
	QFile f;
};

inline std::wstring S(const QString& S) { return { S.toStdWString() }; }
inline QString S(const std::wstring& S) { return QString::fromStdWString(S); }
std::optional<HookParam> ParseCode(QString HCode);
QString GenerateCode(HookParam hp, DWORD processId);

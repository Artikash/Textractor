#pragma once

#include "qtcommon.h"
#include "types.h"

struct QTextFile : QFile
{
	using QFile::QFile;
	QTextFile(const QString& name, QIODevice::OpenMode mode) : QFile(name) { open(mode | QIODevice::Text); }
};

inline std::wstring S(const QString& S) { return { S.toStdWString() }; }
inline QString S(const std::wstring& S) { return QString::fromStdWString(S); }
std::optional<HookParam> ParseCode(QString HCode);
QString GenerateCode(HookParam hp, DWORD processId);

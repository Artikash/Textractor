#pragma once

#include "common.h"
#include <QString>
#include <QVector>
#include <QHash>
#include <QMainWindow>
#include <QDialog>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QRegularExpression>
#include <QSettings>

struct QTextFile : QFile {
    QTextFile(QString name, QIODevice::OpenMode mode) : QFile(name) { open(mode | QIODevice::Text); }
    ~QTextFile() { close(); }
};
inline std::wstring S(const QString& S) { return { S.toStdWString() }; }
inline QString S(const std::wstring& S) { return QString::fromStdWString(S); }
inline HMODULE LoadLibraryOnce(std::wstring fileName) { if (HMODULE module = GetModuleHandleW(fileName.c_str())) return module; return LoadLibraryW(fileName.c_str()); }

#pragma once

#include "common.h"
#include <QString>
#include <QVector>
#include <QHash>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QSettings>
#include <QMainWindow>
#include <QDialog>
#include <QLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QSpinBox>
#include <QListWidget>
#include <QMessageBox>
#include <QInputDialog>

struct QTextFile : QFile { QTextFile(QString name, QIODevice::OpenMode mode) : QFile(name) { open(mode | QIODevice::Text); } };
inline std::wstring S(const QString& S) { return { S.toStdWString() }; }
inline QString S(const std::wstring& S) { return QString::fromStdWString(S); }

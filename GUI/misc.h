#ifndef MISC_H
#define MISC_H

#include <QString>
#include <Windows.h>
#include "../texthook/host.h"

QString GetFullModuleName(DWORD processId, HMODULE module = NULL);
QString GetModuleName(DWORD processId, HMODULE module = NULL);
QStringList GetAllProcesses();
HookParam ParseHCode(QString HCode);
QString GenerateHCode(HookParam hp, DWORD processId);

#endif // MISC_H

#ifndef MISC_H
#define MISC_H

#include <QString>
#include <Windows.h>
#include "../texthook/host.h"

QString GetModuleName(DWORD processId, HMODULE module = NULL);
HookParam ParseHCode(QString HCode, DWORD processId);
QString GenerateHCode(HookParam hp, DWORD processId);

#endif // MISC_H

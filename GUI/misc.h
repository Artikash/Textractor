#ifndef MISC_H
#define MISC_H

#include "qtcommon.h"
#include "types.h"

QString GetFullModuleName(DWORD processId, HMODULE module = NULL);
QString GetModuleName(DWORD processId, HMODULE module = NULL);
QMultiHash<QString, DWORD> GetAllProcesses();
std::optional<HookParam> ParseCode(QString HCode);
QString GenerateCode(HookParam hp, DWORD processId);

static QString CodeInfoDump =
"Enter hook code\r\n\
/H{A|B|W|S|Q|V}[N][codepage#]data_offset[*deref_offset1][:split_offset[*deref_offset2]]@addr[:module[:func]]\r\n\
OR\r\n\
Enter read code\r\n\
/R{S|Q|V}[codepage#][*deref_offset|0]@addr\r\n\
All numbers except codepage in hexadecimal\r\n\
A/B: Shift-JIS char little/big endian\r\n\
W: UTF-16 char\r\n\
S/Q/V: Shift-JIS/UTF-16/UTF-8 string\r\n\
Negatives for data_offset/sub_offset refer to registers\r\n\
-4 for EAX, -8 for ECX, -C for EDX, -10 for EBX, -14 for ESP, -18 for EBP, -1C for ESI, -20 for EDI\r\n\
* means dereference pointer+deref_offset";
#endif // MISC_H

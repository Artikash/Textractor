#include "misc.h"
#include "const.h"
#include <QRegExp>
#include <Psapi.h>

QString GetFullModuleName(DWORD processId, HMODULE module)
{
	HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	wchar_t buffer[MAX_PATH] = {};
	GetModuleFileNameExW(handle, module, buffer, MAX_PATH);
	CloseHandle(handle);
	return QString::fromWCharArray(buffer);
}

QString GetModuleName(DWORD processId, HMODULE module)
{
	QString fullName = GetFullModuleName(processId, module);
	return fullName.remove(0, fullName.lastIndexOf("\\") + 1);
}

std::unordered_map<std::wstring, DWORD> GetAllProcesses()
{
	DWORD allProcessIds[0x1000];
	DWORD spaceUsed;
	std::unordered_map<std::wstring, DWORD> ret;
	if (!EnumProcesses(allProcessIds, sizeof(allProcessIds), &spaceUsed)) return ret;
	for (int i = 0; i < spaceUsed / sizeof(DWORD); ++i)
		if (GetModuleName(allProcessIds[i]).size())
			ret[GetModuleName(allProcessIds[i]).toStdWString()] = allProcessIds[i];
	return ret;
}

namespace
{
	DWORD Hash(QString module)
	{
		module = module.toLower();
		DWORD hash = 0;
		for (auto i : module) hash = _rotr(hash, 7) + i.unicode();
		return hash;
	}

	std::optional<HookParam> ParseRCode(QString RCode)
	{
		HookParam hp = {};
		hp.type |= DIRECT_READ;
		switch (RCode.at(0).unicode())
		{
		case L'S':
			break;
		case L'Q':
			hp.type |= USING_STRING | USING_UNICODE;
			break;
		case L'V':
			hp.type |= USING_STRING | USING_UTF8;
			break;
		default:
			return {};
		}
		RCode.remove(0, 1);
		QRegExp stringGap("^\\-?[\\dA-F]+");
		if (stringGap.indexIn(RCode) == -1) return {};
		hp.offset = stringGap.cap(0).toInt(nullptr, 16);
		RCode.remove(0, stringGap.cap(0).length());
		if (RCode.at(0).unicode() != L'@') return {};
		RCode.remove(0, 1);
		QRegExp address("[\\dA-F]+$");
		if (address.indexIn(RCode) == -1) return {};
		hp.address = address.cap(0).toULongLong(nullptr, 16);
		return hp;
	}

	std::optional<HookParam> ParseHCode(QString HCode)
	{
		HookParam hp = {};
		switch (HCode.at(0).unicode())
		{
		case L'S':
			hp.type |= USING_STRING;
			break;
		case L'A':
			hp.type |= BIG_ENDIAN;
			hp.length_offset = 1;
			break;
		case L'B':
			hp.length_offset = 1;
			break;
		case L'Q':
			hp.type |= USING_STRING | USING_UNICODE;
			break;
		case L'W':
			hp.type |= USING_UNICODE;
			hp.length_offset = 1;
			break;
		case L'V':
			hp.type |= USING_STRING | USING_UTF8;
			break;
		default:
			return {};
		}
		HCode.remove(0, 1);
		if (HCode.at(0).unicode() == L'N')
		{
			hp.type |= NO_CONTEXT;
			HCode.remove(0, 1);
		}
		QRegExp dataOffset("^\\-?[\\dA-F]+");
		if (dataOffset.indexIn(HCode) == -1) return {};
		hp.offset = dataOffset.cap(0).toInt(nullptr, 16);
		HCode.remove(0, dataOffset.cap(0).length());
		QRegExp dataIndirect("^\\*(\\-?[\\dA-F]+)");
		if (dataIndirect.indexIn(HCode) != -1)
		{
			hp.type |= DATA_INDIRECT;
			hp.index = dataIndirect.cap(1).toInt(nullptr, 16);
			HCode.remove(0, dataIndirect.cap(0).length());
		}
		QRegExp split("^\\:(\\-?[\\dA-F]+)");
		if (split.indexIn(HCode) != -1)
		{
			hp.type |= USING_SPLIT;
			hp.split = split.cap(1).toInt(nullptr, 16);
			HCode.remove(0, split.cap(0).length());
			QRegExp splitIndirect("^\\*(\\-?[\\dA-F]+)");
			if (splitIndirect.indexIn(HCode) != -1)
			{
				hp.type |= SPLIT_INDIRECT;
				hp.split_index = splitIndirect.cap(1).toInt(nullptr, 16);
				HCode.remove(0, splitIndirect.cap(0).length());
			}
		}
		if (HCode.at(0).unicode() != L'@') return {};
		HCode.remove(0, 1);
		QRegExp address("^([\\dA-F]+):?");
		if (address.indexIn(HCode) == -1) return {};
		hp.address = address.cap(1).toULongLong(nullptr, 16);
		HCode.remove(address.cap(0));
		if (HCode.length())
		{
			hp.type |= MODULE_OFFSET;
			hp.module = Hash(HCode);
		}
		if (hp.offset < 0)
			hp.offset -= 4;
		if (hp.split < 0)
			hp.split -= 4;
		return hp;
	}

	QString GenerateHCode(HookParam hp, DWORD processId)
	{
		QString code = "/H";
		if (hp.type & USING_UNICODE)
		{
			if (hp.type & USING_STRING)
				code += "Q";
			else
				code += "W";
		}
		else
		{
			if (hp.type & USING_UTF8)
				code += "V";
			else if (hp.type & USING_STRING)
				code += "S";
			else if (hp.type & BIG_ENDIAN)
				code += "A";
			else
				code += "B";
		}
		if (hp.type & NO_CONTEXT)
			code += "N";
		if (hp.offset < 0) hp.offset += 4;
		if (hp.split < 0) hp.split += 4;
		if (hp.offset < 0)
			code += "-" + QString::number(-hp.offset, 16);
		else
			code += QString::number(hp.offset, 16);
		if (hp.type & DATA_INDIRECT)
		{
			if (hp.index < 0)
				code += "*-" + QString::number(-hp.index, 16);
			else
				code += "*" + QString::number(hp.index, 16);
		}
		if (hp.type & USING_SPLIT)
		{
			if (hp.split < 0)
				code += ":-" + QString::number(-hp.split, 16);
			else
				code += ":" + QString::number(hp.split, 16);
		}
		if (hp.type & SPLIT_INDIRECT)
		{
			if (hp.split_index < 0)
				code += "*-" + QString::number(-hp.split_index, 16);
			else
				code += "*" + QString::number(hp.split_index, 16);
		}
		code += "@";
		QString badCode = (code + QString::number(hp.address, 16)).toUpper();
		HANDLE processHandle;
		if (!(processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId))) return badCode;
		MEMORY_BASIC_INFORMATION info;
		if (!VirtualQueryEx(processHandle, (LPCVOID)hp.address, &info, sizeof(info))) return badCode;
		QString moduleName = GetModuleName(processId, (HMODULE)info.AllocationBase);
		if (moduleName.size() == 0) return badCode;
		code += QString::number(hp.address - (DWORD)info.AllocationBase, 16) + ":";
		code = code.toUpper();
		code += moduleName;
		return code;
	}

	QString GenerateRCode(HookParam hp)
	{
		QString code = "/R";
		if (hp.type & USING_UNICODE)
			code += "Q";
		else if (hp.type & USING_UTF8)
			code += "V";
		else
			code += "S";
		code += QString::number(hp.offset, 16);
		code += "@";
		code += QString::number(hp.address, 16);
		return code.toUpper();
	}
}

std::optional<HookParam> ParseCode(QString code)
{
	code = code.toUpper();
	if (code.startsWith("/H")) return ParseHCode(code.remove(0, 2));
	else if (code.startsWith("/R")) return ParseRCode(code.remove(0, 2));
	else return {};
}

QString GenerateCode(HookParam hp, DWORD processId)
{
	if (hp.type & DIRECT_READ) return GenerateRCode(hp);
	else return GenerateHCode(hp, processId);
}

#include "misc.h"
#include "const.h"
#include "defs.h"
#include "host/host.h"
#include "host/util.h"
#include <Psapi.h>
#include <QTextStream>

namespace
{
	std::optional<HookParam> ParseRCode(QString RCode)
	{
		HookParam hp = {};
		hp.type |= DIRECT_READ;

		// {S|Q|V}
		switch (RCode.at(0).unicode())
		{
		case L'S':
			break;
		case L'Q':
			hp.type |= USING_UNICODE;
			break;
		case L'V':
			hp.type |= USING_UTF8;
			break;
		default:
			return {};
		}
		RCode.remove(0, 1);

		// [codepage#]
		QRegularExpressionMatch codepage = QRegularExpression("^([0-9]+)#").match(RCode);
		if (codepage.hasMatch())
		{
			hp.codepage = codepage.captured(1).toInt();
			RCode.remove(0, codepage.captured(0).length());
		}

		// [*deref_offset]
		if (RCode.at(0).unicode() == L'0') RCode.remove(0, 1); // Legacy
		QRegularExpressionMatch deref = QRegularExpression("^\\*(\\-?[[:xdigit:]]+)").match(RCode);
		if (deref.hasMatch())
		{
			hp.type |= DATA_INDIRECT;
			hp.index = deref.captured(1).toInt(nullptr, 16);
			RCode.remove(0, deref.captured(0).length());
		}

		// @addr
		QRegularExpressionMatch address = QRegularExpression("^@([[:xdigit:]]+)$").match(RCode);
		if (!address.hasMatch()) return {};
		hp.address = address.captured(1).toULongLong(nullptr, 16);
		return hp;
	}

	std::optional<HookParam> ParseSCode(QString SCode)
	{
		HookParam hp = {};
		hp.type |= READ_SEARCH;

		// [codepage#]
		QRegularExpressionMatch codepage = QRegularExpression("^([0-9]+)#").match(SCode);
		if (codepage.hasMatch())
		{
			hp.codepage = codepage.captured(1).toInt();
			SCode.remove(0, codepage.captured(0).length());
		}
		else
		{
			hp.codepage = Host::defaultCodepage;
		}

		wcscpy_s<MAX_MODULE_SIZE>(hp.text, S(SCode).c_str());

		return hp;
	}

	std::optional<HookParam> ParseHCode(QString HCode)
	{
		HookParam hp = {};

		// {A|B|W|S|Q|V}
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

		// [N]
		if (HCode.at(0).unicode() == L'N')
		{
			hp.type |= NO_CONTEXT;
			HCode.remove(0, 1);
		}

		// [codepage#]
		QRegularExpressionMatch codepage = QRegularExpression("^([0-9]+)#").match(HCode);
		if (codepage.hasMatch())
		{
			hp.codepage = codepage.captured(1).toInt();
			HCode.remove(0, codepage.captured(0).length());
		}

		// data_offset
		QRegularExpressionMatch dataOffset = QRegularExpression("^\\-?[[:xdigit:]]+").match(HCode);
		if (!dataOffset.hasMatch()) return {};
		hp.offset = dataOffset.captured(0).toInt(nullptr, 16);
		HCode.remove(0, dataOffset.captured(0).length());

		// [*deref_offset1]
		QRegularExpressionMatch deref1 = QRegularExpression("^\\*(\\-?[[:xdigit:]]+)").match(HCode);
		if (deref1.hasMatch())
		{
			hp.type |= DATA_INDIRECT;
			hp.index = deref1.captured(1).toInt(nullptr, 16);
			HCode.remove(0, deref1.captured(0).length());
		}

		// [:split_offset[*deref_offset2]]
		QRegularExpressionMatch splitOffset = QRegularExpression("^\\:(\\-?[[:xdigit:]]+)").match(HCode);
		if (splitOffset.hasMatch())
		{
			hp.type |= USING_SPLIT;
			hp.split = splitOffset.captured(1).toInt(nullptr, 16);
			HCode.remove(0, splitOffset.captured(0).length());

			QRegularExpressionMatch deref2 = QRegularExpression("^\\*(\\-?[[:xdigit:]]+)").match(HCode);
			if (deref2.hasMatch())
			{
				hp.type |= SPLIT_INDIRECT;
				hp.split_index = deref2.captured(1).toInt(nullptr, 16);
				HCode.remove(0, deref2.captured(0).length());
			}
		}

		// @addr[:module[:func]]
		QStringList addressPieces = HCode.split(":");
		QRegularExpressionMatch address = QRegularExpression("^@([[:xdigit:]]+)$").match(addressPieces.at(0));
		if (!address.hasMatch()) return {};
		hp.address = address.captured(1).toULongLong(nullptr, 16);
		if (addressPieces.size() > 1)
		{
			hp.type |= MODULE_OFFSET;
			wcscpy_s<MAX_MODULE_SIZE>(hp.module, S(addressPieces.at(1)).c_str());
		}
		if (addressPieces.size() > 2)
		{
			hp.type |= FUNCTION_OFFSET;
			strcpy_s<MAX_MODULE_SIZE>(hp.function, addressPieces.at(2).toStdString().c_str());
		}

		// ITH has registers offset by 4 vs AGTH: need this to correct
		if (hp.offset < 0) hp.offset -= 4;
		if (hp.split < 0) hp.split -= 4;

		return hp;
	}

	QString GenerateRCode(HookParam hp)
	{
		QString RCode = "R";
		QTextStream codeBuilder(&RCode);

		if (hp.type & USING_UNICODE) codeBuilder << "Q";
		else if (hp.type & USING_UTF8) codeBuilder << "V";
		else codeBuilder << "S";

		if (hp.codepage != 0 && hp.codepage != CP_UTF8) codeBuilder << hp.codepage << "#";

		codeBuilder.setIntegerBase(16);
		codeBuilder.setNumberFlags(QTextStream::UppercaseDigits);

		if (hp.type & DATA_INDIRECT) codeBuilder << "*" << hp.index;

		codeBuilder << "@" << hp.address;

		return RCode;
	}

	QString GenerateHCode(HookParam hp, DWORD processId)
	{
		QString HCode = "H";
		QTextStream codeBuilder(&HCode);

		if (hp.type & USING_UNICODE)
		{
			if (hp.type & USING_STRING) codeBuilder << "Q";
			else codeBuilder << "W";
		}
		else
		{
			if (hp.type & USING_UTF8) codeBuilder << "V";
			else if (hp.type & USING_STRING) codeBuilder << "S";
			else if (hp.type & BIG_ENDIAN) codeBuilder << "A";
			else codeBuilder << "B";
		}
		if (hp.type & NO_CONTEXT) codeBuilder << "N";

		if (hp.codepage != 0 && hp.codepage != CP_UTF8) codeBuilder << hp.codepage << "#";

		codeBuilder.setIntegerBase(16);
		codeBuilder.setNumberFlags(QTextStream::UppercaseDigits);

		if (hp.offset < 0) hp.offset += 4;
		if (hp.split < 0) hp.split += 4;

		codeBuilder << hp.offset;
		if (hp.type & DATA_INDIRECT) codeBuilder << "*" << hp.index;
		if (hp.type & USING_SPLIT) codeBuilder << ":" << hp.split;
		if (hp.type & SPLIT_INDIRECT) codeBuilder << "*" << hp.split_index;

		// Attempt to make the address relative
		if (!(hp.type & MODULE_OFFSET))
			if (AutoHandle<> process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId))
				if (MEMORY_BASIC_INFORMATION info = {}; VirtualQueryEx(process, (LPCVOID)hp.address, &info, sizeof(info)))
					if (auto moduleName = Util::GetModuleFilename(processId, (HMODULE)info.AllocationBase))
					{
						hp.type |= MODULE_OFFSET;
						hp.address -= (uint64_t)info.AllocationBase;
						wcscpy_s<MAX_MODULE_SIZE>(hp.module, moduleName->c_str() + moduleName->rfind(L'\\') + 1);
					}

		codeBuilder << "@" << hp.address;
		if (hp.type & MODULE_OFFSET) codeBuilder << ":" << S(hp.module);
		if (hp.type & FUNCTION_OFFSET) codeBuilder << ":" << hp.function;

		return HCode;
	}
}

std::optional<HookParam> ParseCode(QString code)
{
	if (code.startsWith("/")) code.remove(0, 1); // legacy/AGTH compatibility
	if (code.startsWith("R")) return ParseRCode(code.remove(0, 1));
	else if (code.startsWith("S")) return ParseSCode(code.remove(0, 1));
	else if (code.startsWith("H")) return ParseHCode(code.remove(0, 1));
	else return {};
}

QString GenerateCode(HookParam hp, DWORD processId)
{
	if (hp.type & DIRECT_READ) return GenerateRCode(hp);
	else return GenerateHCode(hp, processId);
}

HMODULE LoadLibraryOnce(std::wstring fileName)
{
	HMODULE module = GetModuleHandleW(fileName.c_str());
	if (!module) module = LoadLibraryW(fileName.c_str());
	return module;
}

TEST(
	assert(ParseCode("/HQN936#-c*C:C*1C@4AA:gdi.dll:GetTextOutA")),
	assert(ParseCode("HB4@0")),
	assert(ParseCode("/RS*10@44")),
	assert(!ParseCode("HQ@4")),
	assert(!ParseCode("/RW@44")),
	assert(!ParseCode("/HWG@33"))
);

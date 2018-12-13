#include "misc.h"
#include "const.h"
#include "host/util.h"
#include <Psapi.h>
#include <Winhttp.h>
#include <QTextStream>

QMultiHash<QString, DWORD> GetAllProcesses()
{
	DWORD allProcessIds[5000] = {}, spaceUsed = 0;
	EnumProcesses(allProcessIds, sizeof(allProcessIds), &spaceUsed);
	QMultiHash<QString, DWORD> ret;
	for (int i = 0; i < spaceUsed / sizeof(DWORD); ++i)
		if (auto processName = Util::GetModuleFileName(allProcessIds[i])) ret.insert(QFileInfo(QString::fromStdWString(processName.value())).fileName(), allProcessIds[i]);
	return ret;
}

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
			hp.type |= USING_STRING | USING_UNICODE;
			break;
		case L'V':
			hp.type |= USING_STRING | USING_UTF8;
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

		// [*deref_offset|0]
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
			wcscpy_s<MAX_MODULE_SIZE>(hp.module, addressPieces.at(1).toStdWString().c_str());
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
		QString RCode = "/R";
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
		QString HCode = "/H";
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
					if (auto moduleName = Util::GetModuleFileName(processId, (HMODULE)info.AllocationBase))
					{
						hp.type |= MODULE_OFFSET;
						hp.address -= (uint64_t)info.AllocationBase;
						wcscpy_s<MAX_MODULE_SIZE>(hp.module, moduleName->c_str() + moduleName->rfind(L'\\') + 1);
					}

		codeBuilder << "@" << hp.address;
		if (hp.type & MODULE_OFFSET) codeBuilder << ":" << QString::fromWCharArray(hp.module);
		if (hp.type & FUNCTION_OFFSET) codeBuilder << ":" << hp.function;

		return HCode;
	}
}

std::optional<HookParam> ParseCode(QString code)
{
	if (code.startsWith("/H")) return ParseHCode(code.remove(0, 2));
	else if (code.startsWith("/R")) return ParseRCode(code.remove(0, 2));
	else return {};
}

QString GenerateCode(HookParam hp, DWORD processId)
{
	if (hp.type & DIRECT_READ) return GenerateRCode(hp);
	else return GenerateHCode(hp, processId);
}

bool UpdateAvailable(std::string currentVersion)
{
	// Queries GitHub releases API https://developer.github.com/v3/repos/releases/ and checks the last release tag to check if it's the same
	struct InternetHandleCloser { void operator()(void* h) { WinHttpCloseHandle(h); } };
	if (AutoHandle<InternetHandleCloser> internet = WinHttpOpen(L"Mozilla/5.0 Textractor", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0))
		if (AutoHandle<InternetHandleCloser> connection = WinHttpConnect(internet, L"api.github.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
			if (AutoHandle<InternetHandleCloser> request = WinHttpOpenRequest(connection, L"GET", L"/repos/Artikash/Textractor/releases", NULL, NULL, NULL, WINHTTP_FLAG_SECURE))
				if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
				{
					DWORD bytesRead;
					char buffer[1000] = {};
					WinHttpReceiveResponse(request, NULL);
					WinHttpReadData(request, buffer, 1000, &bytesRead);
					if (abs(strstr(buffer, "/tag/") - strstr(buffer, currentVersion.c_str())) > 10) return true;
				}
	return false;
}

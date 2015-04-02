/*  Copyright (C) 2010-2012  kaosu (qiupf2000@gmail.com)
 *  This file is part of the Interactive Text Hooker.

 *  Interactive Text Hooker is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ITH.h"
#include "ith/host/srv.h"
#include "ith/common/const.h"
#include "ith/common/types.h"
#include "language.h"
#include "utility.h"

extern HookManager* man;
extern HWND hwndProcessComboBox;

bool Parse(const std::wstring& cmd, HookParam& hp)
{
	using std::wregex;
	using std::regex_search;
	// /H[X]{A|B|W|S|Q}[N][data_offset[*drdo]][:sub_offset[*drso]]@addr[:[module[:{name|#ordinal}]]]
	wregex rx(L"^X?([ABWSQ])(N)?", wregex::icase);
	std::match_results<std::wstring::const_iterator> m;
	auto start = cmd.begin();
	auto end = cmd.end();
	bool result = regex_search(start, end, m, rx);
	if (!result)
		return result;
	start = m[0].second;
	if (m[2].matched)
		hp.type |= NO_CONTEXT;

	switch (m[1].first[0])
	{
	case L's':
	case L'S':
		hp.type |= USING_STRING;
		break;
	case L'e':
	case L'E':
		hp.type |= STRING_LAST_CHAR;
	case L'a':
	case L'A':
		hp.type |= BIG_ENDIAN;
		hp.length_offset = 1;
		break;
	case L'b':
	case L'B':
		hp.length_offset = 1;
		break;
	case L'h':
	case L'H':
		hp.type |= PRINT_DWORD;
	case L'q':
	case L'Q':
		hp.type |= USING_STRING | USING_UNICODE;
		break;
	case L'l':
	case L'L':
		hp.type |= STRING_LAST_CHAR;
	case L'w':
	case L'W':
		hp.type |= USING_UNICODE;
		hp.length_offset = 1;
		break;
	default:
		break;
	}

	// [data_offset[*drdo]]
	std::wstring data_offset(L"(-?[[:xdigit:]]+)"), drdo(L"(\\*-?[[:xdigit:]]+)?");
	rx = wregex(L"^"+ data_offset + drdo, wregex::icase);
	result = regex_search(start, end, m, rx);
	if (result)
	{
		start = m[0].second;
		hp.off = std::stoul(m[1].str(), NULL, 16);
		if (m[2].matched)
		{
			hp.type |= DATA_INDIRECT;
			hp.ind = std::stoul(m[2].str().substr(1), NULL, 16);
		}
	}

	// [:sub_offset[*drso]]
	std::wstring sub_offset(L"(-?[[:xdigit:]]+)"), drso(L"(\\*-?[[:xdigit:]]+)?");
	rx = wregex(L"^:" + sub_offset +  drso, wregex::icase);
	result = regex_search(start, end, m, rx);
	if (result)
	{
		start = m[0].second;
		hp.type |= USING_SPLIT;
		hp.split = std::stoul(m[1].str(), NULL, 16);
		if (m[2].matched)
		{
			hp.type |= SPLIT_INDIRECT;
			hp.split_ind = std::stoul(m[2].str().substr(1), NULL, 16);
		}
	}
	// @addr
	rx = wregex(L"^@[[:xdigit:]]+", wregex::icase);
	result = regex_search(start, end, m, rx);
	if (!result)
		return false;
	start = m[0].second;
	hp.addr = std::stoul(m[0].str().substr(1), NULL, 16);
	if (hp.off & 0x80000000)
		hp.off -= 4;
	if (hp.split & 0x80000000)
		hp.split -= 4;

	// [:[module[:{name|#ordinal}]]]
	// ":"               ->
	// ""                -> MODULE_OFFSET && module == NULL && function == addr
	// ":GDI.dll"        -> MODULE_OFFSET && module != NULL
	// ":GDI.dll:strlen" -> MODULE_OFFSET | FUNCTION_OFFSET && module != NULL && function != NULL
	// ":GDI.dll:#123"   -> MODULE_OFFSET | FUNCTION_OFFSET && module != NULL && function != NULL
	std::wstring module(L"([[:graph:]]+)"), name(L"[[:graph:]]+"), ordinal(L"\\d+");
	rx = wregex(L"^:(" + module + L"(:" + name + L"|#" + ordinal + L")?)?$", wregex::icase);
	result = regex_search(start, end, m, rx);
	if (result) // :[module[:{name|#ordinal}]]
	{
		if (m[1].matched) // module
		{
			hp.type |= MODULE_OFFSET;
			std::wstring module = m[2];
			std::transform(module.begin(), module.end(), module.begin(), ::towlower);
			hp.module = Hash(module);
			if (m[3].matched) // :name|#ordinal
			{
				hp.type |= FUNCTION_OFFSET;
				hp.function = Hash(m[3].str().substr(1));
			}
		}
	}
	else
	{
		rx = wregex(L"^!([[:xdigit:]]+)(!([[:xdigit:]]+))?$", wregex::icase);
		result = regex_search(start, end, m, rx);
		if (result)
		{
			hp.type |= MODULE_OFFSET;
			hp.module = std::stoul(m[1].str(), NULL, 16);
			if (m[2].matched)
			{
				hp.type |= FUNCTION_OFFSET;
				hp.function = std::stoul(m[2].str().substr(1), NULL, 16);
			}
		}
		else
		{
			hp.type |= MODULE_OFFSET;
			hp.function = hp.addr;
		}
	}
	return true;
}

DWORD ProcessCommand(const std::wstring& cmd, DWORD pid)
{
	using std::wregex;
	using std::regex_match;
	std::match_results<std::wstring::const_iterator> m;

	if (regex_match(cmd, m, wregex(L"/pn(.+)", wregex::icase)))
	{
		pid = IHF_GetPIDByName(m[1].str().c_str());
		if (pid == 0)
			return 0;
		IHF_InjectByPID(pid);
	}
	else if (regex_match(cmd, m, wregex(L"/p(\\d+)", wregex::icase)))
	{
		pid = std::stoul(m[1].str());
		IHF_InjectByPID(pid);
	}
	else if (regex_match(cmd, m, wregex (L"/h(.+)", wregex::icase)))
	{
		HookParam hp = {};
		if (Parse(m[1].str(), hp))
			IHF_InsertHook(pid, &hp);
	}
	else if (regex_match(cmd, m, wregex(L":l([[:xdigit:]]+)-([[:xdigit:]]+)", wregex::icase)))
	{
		DWORD from = std::stoul(m[1].str(), NULL, 16);
		DWORD to = std::stoul(m[2].str(), NULL, 16);
		IHF_AddLink(from, to);
	}
	else if (regex_match(cmd, m, wregex(L":u([[:xdigit:]]+)", wregex::icase)))
	{
		DWORD from = std::stoul(m[1].str(), NULL, 16);
		IHF_UnLink(from);
	}
	else if (regex_match(cmd, m, wregex(L":(?:h|help)", wregex::icase)))
	{
		ConsoleOutput(Usage);
	}
	else
	{
		ConsoleOutput(L"Unknown command. Type :h or :help for help.");
	}
	return 0;
}

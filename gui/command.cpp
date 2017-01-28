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
#include "host/host.h"
#include "vnrhook/include/const.h"
#include "vnrhook/include/types.h"
#include "language.h"
#include "utility.h"
#include "profile/misc.h"

extern HookManager* man;
extern HWND hwndProcessComboBox;

DWORD ProcessCommand(const std::wstring& cmd, DWORD pid)
{
	using std::wregex;
	using std::regex_match;
	std::match_results<std::wstring::const_iterator> m;

	if (regex_match(cmd, m, wregex(L"/pn(.+)", wregex::icase)))
	{
		pid = Host_GetPIDByName(m[1].str().c_str());
		if (pid == 0)
			return 0;
		Host_InjectByPID(pid);
	}
	else if (regex_match(cmd, m, wregex(L"/p(\\d+)", wregex::icase)))
	{
		pid = std::stoul(m[1].str());
		Host_InjectByPID(pid);
	}
	else if (regex_match(cmd, m, wregex(L"/h(.+)", wregex::icase)))
	{
		HookParam hp = {};
		if (Parse(m[1].str(), hp))
			Host_InsertHook(pid, &hp);
	}
	else if (regex_match(cmd, m, wregex(L"(?::|)(?:ㅇ|연|l|)([[:xdigit:]]+)(?:-| )([[:xdigit:]]+)", wregex::icase)))
	{
		DWORD from = std::stoul(m[1].str(), NULL, 16);
		DWORD to = std::stoul(m[2].str(), NULL, 16);
		Host_AddLink(from, to);
	}
	else if (regex_match(cmd, m, wregex(L"(?::|)(?:ㅎ|해|해제|u)([[:xdigit:]]+)", wregex::icase)))
	{
		DWORD from = std::stoul(m[1].str(), NULL, 16);
		Host_UnLink(from);
	}
	else if (regex_match(cmd, m, wregex(L"(?::|)(?:ㄷ|도|도움|도움말|h|help)", wregex::icase)))
	{
		ConsoleOutput(Usage);
	}
	else
	{
		ConsoleOutput(L"알 수 없는 명령어. 도움말을 보시려면, :h 나 :help를 입력하세요.");
	}
	return 0;
}

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

	if (regex_match(cmd, m, wregex(L"/p(\\d+)", wregex::icase)))
	{
		pid = std::stoul(m[1].str());
		InjectProcessById(pid);
	}
	else if (regex_match(cmd, m, wregex(L"/h(.+)", wregex::icase)))
	{
		HookParam hp = {};
		if (Parse(m[1].str(), hp))
			Host_InsertHook(pid, &hp);
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

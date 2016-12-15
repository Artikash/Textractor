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

#pragma once

#include "ITH.h"

typedef void (*CustomFilterCallBack) (WORD, PVOID);

class CustomFilter
{
public:
	bool Find(WORD number) const;
	void Insert(WORD number);
	void Erase(WORD number);
	void Clear();
	void Traverse(CustomFilterCallBack callback, PVOID param);
private:
	std::set<WORD> set;
};

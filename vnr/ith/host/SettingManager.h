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
#include "config.h"
#include <intrin.h>
#define SETTING_SPLIT_TIME 0
#define SETTING_CYCLIC_REMOVE 1
#define SETTING_REPEAT_COUNT 2
#define SETTING_CLIPFLAG 3
#define SETTING_MAX_INDEX 4
class IHFSERVICE SettingManager
{
public:
	SettingManager() {memset(setting_int,0,sizeof(setting_int));}
	~SettingManager(){}
	unsigned int SetValue(unsigned int index, unsigned int value)
	{
		if (index < SETTING_MAX_INDEX)
			return (unsigned int)_InterlockedExchange((long*)setting_int+index,(long)value);
		else return 0;
	}
	unsigned int GetValue(unsigned int index)
	{
		if (index < SETTING_MAX_INDEX)
			return setting_int[index];
		else return 0;
	}
private:
	unsigned int setting_int[SETTING_MAX_INDEX];

};
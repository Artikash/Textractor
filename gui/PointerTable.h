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

template <class T, unsigned int default_size>
class PointerTable
{
public:
	PointerTable()
	{
		assert((default_size & (default_size - 1)) == 0);
		size = default_size;
		table = new T*[size];
		used = 0;
		next = 0;
		memset(table, 0, size * sizeof(T*));
	}
	~PointerTable()
	{
		delete table;
	}
	T* Set(unsigned int number, T* ptr)
	{
		if (number >= size - 2)
		{
			unsigned int new_size = size;
			while (number >= new_size - 2) new_size <<= 1;
			Resize(new_size);
		}
		T* original = table[number + 1];
		table[number + 1] = ptr;
		if (ptr == 0) //Clear pointer.
		{
			if (number < next) next = number;
			if (number == used - 1) //Last used position is cleared.
			{
				table[0] = (T*)1;
				for (used--; table[used] == 0; used--);
			}
		}
		else //Set pointer.
		{
			__assume(number < size - 2); //Otherwise a resize operation is invoked.
			if (number == next)
			{
				next++; //Next position is occupied.
				for (next++; table[next]; next++); //There is always a zero in the end.
				next--; //next is zero based but the table start at one(zero is used as sentry).
			}
			if (number >= used) used = number + 1;
		}
		return original;
	}
	T* Get(unsigned int number)
	{
		number++;
		if (number <= used) return table[number];
		else return 0;
	}
	T* operator [](unsigned int number)
	{
		number++;
		if (number <= used) return table[number];
		else return 0;
	}
	void Append(T* ptr)
	{
		Set(next,ptr);
	}
	void Resize(unsigned int new_size)
	{
		assert(new_size > size);
		assert((new_size & (new_size - 1)) == 0);
		assert(new_size < 0x10000);

		T** temp = new T*[new_size];
		memcpy(temp, table, size * sizeof(T*));
		memset(temp + size, 0, (new_size - size) * sizeof(T*));
		delete table;
		size = new_size;
		table = temp;
	}
	void DeleteAll() //Release all pointers on demand.
	{
		T* p;
		next = 0;
		while (used)
		{
			p = table[used];
			if (p) delete p;
			table[used] = 0;
			used--;
		}
	}
	void Reset() //Reset without release pointers.
	{
		memset(table, 0, sizeof(T*) * (used + 1));
		next = 0;
		used = 0;

	}
	unsigned int size,next,used;
	T** table;
};

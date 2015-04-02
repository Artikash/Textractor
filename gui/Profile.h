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
#include "ith/common/types.h" // HookParam

struct ThreadParameter;

#define THREAD_MASK_RETN 1
#define THREAD_MASK_SPLIT 2

class HookProfile
{
	HookParam hp;
	std::wstring name;
public:
	HookProfile(const HookParam& hp, const std::wstring& name):
		hp(hp),
		name(name)
	{}
	const HookParam& HP() const { return hp; };
	const std::wstring& Name() const { return name; };
};

class ThreadProfile
{
	std::wstring hook_name;
	DWORD retn;
	DWORD split;
	DWORD hook_addr;
	WORD hm_index, flags;
	std::wstring comment;
public:
	ThreadProfile(const std::wstring& hook_name,
		DWORD retn,
		DWORD split,
		DWORD hook_addr,
		WORD hm_index,
		WORD flags,
		const std::wstring& comment) :
		hook_name(hook_name),
		retn(retn),
		split(split),
		hook_addr(hook_addr),
		hm_index(hm_index),
		flags(flags),
		comment(comment)
	{
	}
	const std::wstring& HookName() const { return hook_name; }
	const std::wstring& Comment() const { return comment; }
	DWORD Return() const { return retn; }
	DWORD Split() const { return split; }
	DWORD& HookAddress() { return hook_addr; }
	WORD& HookManagerIndex() { return hm_index; }
	WORD Flags() const { return flags; }
};

class LinkProfile
{
	WORD from_index, to_index;
public:
	LinkProfile(WORD from_index, WORD to_index):
		from_index(from_index),
		to_index(to_index)
	{}
	WORD FromIndex() const { return from_index; }
	WORD ToIndex() const { return to_index; }
};

typedef std::unique_ptr<HookProfile> hook_ptr;
typedef std::unique_ptr<ThreadProfile> thread_ptr;
typedef std::unique_ptr<LinkProfile> link_ptr;

class Profile
{
public:
	Profile(const std::wstring& title);
	bool XmlReadProfile(pugi::xml_node profile_node);
	bool XmlWriteProfile(pugi::xml_node profile_node);
	int AddHook(const HookParam& hp, const std::wstring& name);
	int AddThread(thread_ptr tp);
	int AddLink(link_ptr lp);
	void Clear();
	const std::vector<hook_ptr>& Hooks() const;
	const std::vector<thread_ptr>& Threads() const;
	const std::vector<link_ptr>& Links() const;
	const std::wstring& Title() const;
	std::vector<thread_ptr>::const_iterator FindThreadProfile(const ThreadParameter& tp) const;
	WORD& SelectedIndex() { return select_index; }

private:
	void RemoveLink(DWORD index);
	void RemoveHook(DWORD index);
	void RemoveThread(DWORD index);

	bool XmlReadProfileHook(pugi::xml_node hooks_node);
	bool XmlReadProfileThread(pugi::xml_node threads_node);
	bool XmlReadProfileLink(pugi::xml_node links_node);
	bool XmlWriteProfileHook(pugi::xml_node hooks_node);
	bool XmlWriteProfileThread(pugi::xml_node threads_node);
	bool XmlWriteProfileLink(pugi::xml_node links_node);

	std::wstring title;
	std::vector<hook_ptr> hooks;
	std::vector<thread_ptr> threads;
	std::vector<link_ptr> links;

	WORD select_index;
};

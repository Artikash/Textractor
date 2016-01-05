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

#include "vnrhook/include/types.h" // HookParam
#include <string>
#include <memory>
#include <vector>
#include <unordered_set>

struct ThreadParameter;
class TextThread;
class HookProfile;
class ThreadProfile;
class LinkProfile;
typedef std::unique_ptr<HookProfile> hook_ptr;
typedef std::unique_ptr<ThreadProfile> thread_ptr;
typedef std::unique_ptr<LinkProfile> link_ptr;
typedef std::vector<thread_ptr>::const_iterator thread_ptr_iter;
namespace pugi {
	class xml_node;
}

#define THREAD_MASK_RETN 1
#define THREAD_MASK_SPLIT 2

class HookProfile
{
	HookParam hp;
	std::wstring name;
public:
	HookProfile(const HookParam& hp, const std::wstring& name) :
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
	LinkProfile(WORD from_index, WORD to_index) :
		from_index(from_index),
		to_index(to_index)
	{}
	WORD FromIndex() const { return from_index; }
	WORD ToIndex() const { return to_index; }
};

namespace std {
	template<>
	struct hash<hook_ptr> {
		size_t operator()(const hook_ptr &r) const
		{
			return hash<DWORD>{}(r->HP().address)
				^ hash<DWORD>{}(r->HP().module)
				^ hash<DWORD>{}(r->HP().function);
		}
	};
	template<>
	struct equal_to<hook_ptr> {
		bool operator()(const hook_ptr& r, const hook_ptr& r2) const
		{
			return r->HP().address == r2->HP().address
				&& r->HP().module == r2->HP().module
				&& r->HP().function == r2->HP().function;
		}
	};

	template<>
	struct hash<link_ptr> {
		size_t operator()(const link_ptr &r) const
		{
			return hash<WORD>{}(r->FromIndex())
				^ hash<WORD>{}(r->ToIndex());
		}
	};
	template<>
	struct equal_to<link_ptr> {
		bool operator()(const link_ptr& r, const link_ptr& r2) const
		{
			return r->FromIndex() == r2->FromIndex()
				&& r->ToIndex() == r2->ToIndex();
		}
	};
}

class Profile
{
public:
	Profile(const std::wstring& title);
	bool XmlReadProfile(pugi::xml_node profile_node);
	bool XmlWriteProfile(pugi::xml_node profile_node);
	void AddHook(hook_ptr hook);
	int AddThread(thread_ptr tp);
	void AddLink(link_ptr lp);
	void Clear();
	const std::unordered_set<hook_ptr>& Hooks() const;
	const std::vector<thread_ptr>& Threads() const;
	const std::unordered_set<link_ptr>& Links() const;
	const std::wstring& Title() const;
	thread_ptr_iter FindThread(const ThreadParameter* tp, const std::wstring& hook_name) const;
	WORD& SelectedIndex() { return select_index; }
	bool IsThreadSelected(thread_ptr_iter thread_profile);

private:
	bool XmlReadProfileHook(pugi::xml_node hooks_node);
	bool XmlReadProfileThread(pugi::xml_node threads_node);
	bool XmlReadProfileLink(pugi::xml_node links_node);
	bool XmlWriteProfileHook(pugi::xml_node hooks_node);
	bool XmlWriteProfileThread(pugi::xml_node threads_node);
	bool XmlWriteProfileLink(pugi::xml_node links_node);

	std::wstring title;
	std::unordered_set<hook_ptr> hooks;
	std::vector<thread_ptr> threads;
	std::unordered_set<link_ptr> links;

	WORD select_index;
};

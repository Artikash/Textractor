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


#include "host.h"
#include "hookman.h"
#include "vnrhook/include/types.h"
#include "vnrhook/include/const.h"
#include "Profile.h"
#include "misc.h"
#include <algorithm>
#include "pugixml.h"

extern HookManager* man;

Profile::Profile(const std::wstring& title) :
select_index(-1),
title(title)
{}

const std::unordered_set<hook_ptr>& Profile::Hooks() const
{
	return hooks;
}

const std::vector<thread_ptr>& Profile::Threads() const
{
	return threads;
}

const std::unordered_set<link_ptr>& Profile::Links() const
{
	return links;
}

bool Profile::XmlReadProfile(pugi::xml_node profile)
{
	auto hooks_node = profile.child(L"Hooks");
	auto threads_node = profile.child(L"Threads");
	auto links_node = profile.child(L"Links");
	if (hooks_node && !XmlReadProfileHook(hooks_node))
		return false;
	if (threads_node && !XmlReadProfileThread(threads_node))
		return false;
	if (links_node && !XmlReadProfileLink(links_node))
		return false;
	auto select_node = profile.child(L"Select");
	if (select_node)
	{
		auto thread_index = select_node.attribute(L"ThreadIndex");
		if (!thread_index)
			return false;
		DWORD tmp_select = std::stoul(thread_index.value(), NULL, 16);
		select_index = tmp_select & 0xFFFF;
	}
	return true;
}

bool Profile::XmlReadProfileHook(pugi::xml_node hooks_node)
{
	for (auto hook = hooks_node.begin(); hook != hooks_node.end(); ++hook)
	{
		std::wstring name = hook->name();
		if (name.empty() || name.compare(L"Hook") != 0)
			return false;
		auto type = hook->attribute(L"Type");
		if (!type || type.empty())
			return false;
		auto code = hook->attribute(L"Code");
		if (!code)
			return false;
		std::wstring code_value = code.value();
		HookParam hp = {};
		switch (type.value()[0])
		{
		case L'H':
			if (code_value[0] != L'/')
				return false;
			if (code_value[1] != L'H' && code_value[1] != L'h')
				return false;
			if (Parse(code_value.substr(2), hp))
			{
				auto name = hook->attribute(L"Name");
				if (!name || name.empty())
					AddHook(hook_ptr(new HookProfile(hp, L"")));
				else
					AddHook(hook_ptr(new HookProfile(hp, name.value())));
			}
			break;
		default:
			return false;
		}
	}
	return true;
}

bool Profile::XmlReadProfileThread(pugi::xml_node threads_node)
{
	std::wstring hook_name_buffer;
	for (auto thread = threads_node.begin(); thread != threads_node.end(); ++thread)
	{
		std::wstring name = thread->name();
		if (name.empty() || name.compare(L"Thread") != 0)
			return false;
		auto hook_name = thread->attribute(L"HookName");
		if (!hook_name)
			return false;
		auto context = thread->attribute(L"Context");
		if (!context)
			return false;
		auto sub_context = thread->attribute(L"SubContext");
		if (!sub_context)
			return false;
		auto mask = thread->attribute(L"Mask");
		if (!mask)
			return false;
		DWORD mask_tmp = std::stoul(mask.value(), NULL, 16);
		auto comment = thread->attribute(L"Comment");
		auto retn = std::stoul(context.value(), NULL, 16);
		auto split = std::stoul(sub_context.value(), NULL, 16);
		WORD flags = mask_tmp & 0xFFFF;
		auto tp = new ThreadProfile(hook_name.value(), retn, split, 0, 0, flags,
			comment.value());
		AddThread(thread_ptr(tp));
	}
	return true;
}

bool Profile::XmlReadProfileLink(pugi::xml_node links_node)
{
	for (auto link = links_node.begin(); link != links_node.end(); ++link)
	{
		std::wstring name = link->name();
		if (name.empty() || name.compare(L"Link") != 0)
			return false;
		auto from = link->attribute(L"From");
		if (!from)
			return false;
		DWORD link_from = std::stoul(from.value(), NULL, 16);
		auto to = link->attribute(L"To");
		if (!to)
			return false;
		DWORD link_to = std::stoul(to.value(), NULL, 16);
		auto lp = new LinkProfile(link_from & 0xFFFF, link_to & 0xFFFF);
		AddLink(link_ptr(lp));
	}
	return true;
}

bool Profile::XmlWriteProfile(pugi::xml_node profile_node)
{
	if (!hooks.empty())
	{
		auto node = profile_node.append_child(L"Hooks");
		XmlWriteProfileHook(node);
	}
	if (!threads.empty())
	{
		auto node = profile_node.append_child(L"Threads");
		XmlWriteProfileThread(node);
	}
	if (!links.empty())
	{
		auto node = profile_node.append_child(L"Links");
		XmlWriteProfileLink(node);
	}
	if (select_index != 0xFFFF)
	{
		auto node = profile_node.append_child(L"Select");
		node.append_attribute(L"ThreadIndex") = select_index;
	}
	return true;
}

bool Profile::XmlWriteProfileHook(pugi::xml_node hooks_node)
{
	for (auto hook = hooks.begin(); hook != hooks.end(); ++hook)
	{
		auto hook_node = hooks_node.append_child(L"Hook");
		hook_node.append_attribute(L"Type") = L"H";
		hook_node.append_attribute(L"Code") = ParseCode((*hook)->HP()).c_str();
		if (!(*hook)->Name().empty())
			hook_node.append_attribute(L"Name") = (*hook)->Name().c_str();
	}
	return true;
}

bool Profile::XmlWriteProfileThread(pugi::xml_node threads_node)
{
	for (auto thread = threads.begin(); thread != threads.end(); ++thread)
	{
		const std::wstring& name = (*thread)->HookName();
		if (name.empty())
			return false;
		auto node = threads_node.append_child(L"Thread");
		node.append_attribute(L"HookName") = name.c_str();
		std::wstring hex = ToHexString((*thread)->Flags() & (THREAD_MASK_RETN | THREAD_MASK_SPLIT));
		node.append_attribute(L"Mask") = hex.c_str();
		hex = ToHexString((*thread)->Split());
		node.append_attribute(L"SubContext") = hex.c_str();
		hex = ToHexString((*thread)->Return());
		node.append_attribute(L"Context") = hex.c_str();
		if (!(*thread)->Comment().empty())
			node.append_attribute(L"Comment") = (*thread)->Comment().c_str();
	}
	return true;
}

bool Profile::XmlWriteProfileLink(pugi::xml_node links_node)
{
	for (auto link = links.begin(); link != links.end(); ++link)
	{
		auto node = links_node.append_child(L"Link");
		node.append_attribute(L"From") = ToHexString((*link)->FromIndex()).c_str();
		node.append_attribute(L"To") = ToHexString((*link)->ToIndex()).c_str();
	}
	return true;
}

void Profile::Clear()
{
	title = L"";
	select_index = -1;
	hooks.clear();
	threads.clear();
	links.clear();
}

void Profile::AddHook(hook_ptr hook)
{
	hooks.insert(std::move(hook));
}

// add the thread profile and return its index
int Profile::AddThread(thread_ptr tp)
{
	auto it = std::find_if(threads.begin(), threads.end(), [&tp](thread_ptr& thread)
	{
		return thread->HookName().compare(tp->HookName()) == 0 &&
			thread->Return() == tp->Return() &&
			thread->Split() == tp->Split();
	});
	if (it != threads.end())
		return it - threads.begin();
	threads.push_back(std::move(tp));
	return threads.size() - 1;
}

void Profile::AddLink(link_ptr link)
{
	links.insert(std::move(link));
}

const std::wstring& Profile::Title() const
{
	return title;
}

bool Profile::IsThreadSelected(thread_ptr_iter thread_profile)
{
	if (thread_profile != threads.end())
	{
		auto thread_index = thread_profile - threads.begin();
		return select_index == thread_index;
	}
	return false;
}

thread_ptr_iter Profile::FindThread(const ThreadParameter* tp, const std::wstring& hook_name) const
{
	auto thread_profile = std::find_if(threads.begin(), threads.end(),
		[&tp, &hook_name](const thread_ptr& thread_profile) -> bool
	{
		return thread_profile->HookName().compare(hook_name) == 0
			&& thread_profile->Return() == tp->retn
			&& thread_profile->Split() == tp->spl;
	});
	return thread_profile;
}

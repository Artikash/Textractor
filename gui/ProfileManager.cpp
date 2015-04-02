#include "ProfileManager.h"
#include "Profile.h"
#include "ith/host/srv.h"
#include "ith/host/hookman.h"
#include "ith/common/types.h"
#include "ith/common/const.h"

extern HookManager* man; // main.cpp
extern LONG auto_inject, auto_insert, inject_delay; // main.cpp
extern LONG insert_delay, process_time; // main.cpp
bool MonitorFlag;
ProfileManager* pfman;

DWORD WINAPI MonitorThread(LPVOID lpThreadParameter);
void AddHooksToProfile(Profile& pf, const ProcessRecord& pr);
void AddThreadsToProfile(Profile& pf, const ProcessRecord& pr, DWORD pid);
DWORD AddThreadToProfile(Profile& pf, const ProcessRecord& pr, TextThread& thread);
void MakeHookRelative(const ProcessRecord& pr, HookParam& hp);
std::wstring GetHookNameByAddress(const ProcessRecord& pr, DWORD hook_address);
void GetHookNameToAddressMap(const ProcessRecord& pr, std::map<std::wstring, DWORD>& hookNameToAddress);

ProfileManager::ProfileManager():
hMonitorThread(IthCreateThread(MonitorThread, 0))
{
	LoadProfile();
}
ProfileManager::~ProfileManager()
{
	SaveProfile();
	WaitForSingleObject(hMonitorThread.get(), 0);
}

Profile* ProfileManager::GetProfile(DWORD pid)
{
	std::wstring path = GetProcessPath(pid);
	if (!path.empty())
	{
		auto node = profile_tree.find(path);
		if (node != profile_tree.end())
			return node->second.get();
	}
	return NULL;
}

bool ProfileManager::AddProfile(pugi::xml_node game)
{
	auto file = game.child(L"File");
	auto profile = game.child(L"Profile");
	if (!file || !profile)
		return false;
	auto path = file.attribute(L"Path");
	if (!path)
		return false;
	auto profile_title = game.attribute(L"Title");
	auto title = profile_title ? profile_title.value() : L"";
	auto pf = new Profile(title);
	if (!pf->XmlReadProfile(profile))
		return false;
	AddProfile(path.value(), profile_ptr(pf));
	return true;
}

Profile* ProfileManager::AddProfile(const std::wstring& path, DWORD pid)
{
	CSLock lock(cs);
	auto& pf = profile_tree[path];
	if (!pf)
	{
		std::wstring title = GetProcessTitle(pid);
		pf.reset(new Profile(title));
	}
	return pf.get();
}

Profile* ProfileManager::AddProfile(const std::wstring& path, profile_ptr new_profile)
{
	CSLock lock(cs);
	auto& pf = profile_tree[path];
	if (!pf)
		pf.swap(new_profile);
	return pf.get();
}

void ProfileManager::WriteProfileXml(const std::wstring& path, Profile& pf, pugi::xml_node root)
{
	auto game = root.append_child(L"Game");
	auto file_node = game.append_child(L"File");
	file_node.append_attribute(L"Path") = path.c_str();
	auto profile_node = game.append_child(L"Profile");
	pf.XmlWriteProfile(profile_node);
	if (!pf.Title().empty())
	{
		if (!game.attribute(L"Title"))
			game.append_attribute(L"Title");
		game.attribute(L"Title") = pf.Title().c_str();
	}
}

void ProfileManager::LoadProfile()
{
	pugi::xml_document doc;
	UniqueHandle hFile(IthCreateFile(L"ITH_Profile.xml", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING));
	if (hFile.get() == INVALID_HANDLE_VALUE)
		return;
	DWORD size = GetFileSize(hFile.get(), NULL);
	std::unique_ptr<char[]> buffer(new char[size]);
	ReadFile(hFile.get(), buffer.get(), size, &size, NULL);
	auto result = doc.load_buffer(buffer.get(), size);
	if (!result)
		return;
	auto root = doc.root().child(L"ITH_Profile");
	if (!root)
		return;
	for (auto game = root.begin(); game != root.end(); ++game)
		AddProfile(*game);
}

void ProfileManager::SaveProfile()
{
	pugi::xml_document doc;
	auto root = doc.append_child(L"ITH_Profile");
	for (auto it = profile_tree.begin(); it != profile_tree.end(); ++it) {
		auto& path = it->first;
		auto& profile = it->second;
		WriteProfileXml(path, *profile, root);
	}
	UniqueHandle hFile(IthCreateFile(L"ITH_Profile.xml", GENERIC_WRITE, 0, CREATE_ALWAYS));
	if (hFile.get() != INVALID_HANDLE_VALUE)
	{
		FileWriter fw(hFile.get());
		doc.save(fw);
	}
}

void ProfileManager::DeleteProfile(const std::wstring& path)
{
	CSLock lock(cs);
	profile_tree.erase(profile_tree.find(path));
}

void ProfileManager::FindProfileAndUpdateHookAddresses(DWORD pid, const std::wstring& path)
{
	if (path.empty())
		return;
	auto it = profile_tree.find(path);
	if (it == profile_tree.end())
		return;
	auto& pf = it->second;
	const ProcessRecord* pr = man->GetProcessRecord(pid);
	if (pr == NULL)
		return;
	// hook name -> hook address
	std::map<std::wstring, DWORD> hookNameToAddress;
	GetHookNameToAddressMap(*pr, hookNameToAddress);
	for (auto thread_profile = pf->Threads().begin(); thread_profile != pf->Threads().end();
		++thread_profile)
	{
		auto it = hookNameToAddress.find((*thread_profile)->HookName());
		if (it != hookNameToAddress.end())
			(*thread_profile)->HookAddress() = it->second;
	}
}

void GetHookNameToAddressMap(const ProcessRecord& pr,
	std::map<std::wstring, DWORD>& hookNameToAddress)
{
	WaitForSingleObject(pr.hookman_mutex, 0);
	auto hooks = (const Hook*)pr.hookman_map;
	for (DWORD i = 0; i < MAX_HOOK; ++i)
	{
		if (hooks[i].Address() == 0)
			continue;
		auto& hook = hooks[i];
		std::unique_ptr<WCHAR[]> name(new WCHAR[hook.NameLength() * 2]);
		if (ReadProcessMemory(pr.process_handle, hook.Name(), name.get(), hook.NameLength() * 2, NULL))
			hookNameToAddress[name.get()] = hook.Address();
	}
	ReleaseMutex(pr.hookman_mutex);
}

bool ProfileManager::HasProfile(const std::wstring& path)
{
	return profile_tree.find(path) != profile_tree.end();
}

DWORD ProfileManager::ProfileCount()
{
	return profile_tree.size();
}

DWORD WINAPI InjectThread(LPVOID lpThreadParameter)
{
	DWORD pid = (DWORD)lpThreadParameter;
	Sleep(inject_delay);
	if (man == NULL)
		return 0;
	DWORD status = IHF_InjectByPID(pid);
	if (!auto_insert)
		return status;
	if (status == -1)
		return status;
	Sleep(insert_delay);
	const Profile* pf = pfman->GetProfile(pid);
	if (pf)
	{
		SendParam sp;
		sp.type = 0;
		for (auto hp = pf->Hooks().begin(); hp != pf->Hooks().end(); ++hp)
			IHF_InsertHook(pid, const_cast<HookParam*>(&(*hp)->HP()), (*hp)->Name().c_str());
	}
	return status;
}

DWORD WINAPI MonitorThread(LPVOID lpThreadParameter)
{
	while (MonitorFlag)
	{
		DWORD aProcesses[1024],	cbNeeded, cProcesses;
		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
			break;
		cProcesses = cbNeeded / sizeof(DWORD);
		for (size_t i = 0; i < cProcesses; ++i)
		{
			Sleep(process_time);
			if (!auto_inject || man == NULL || man->GetProcessRecord(aProcesses[i]))
				continue;
			std::wstring process_path = GetProcessPath(aProcesses[i]);
			if (!process_path.empty() && pfman->HasProfile(process_path))
			{
				UniqueHandle hThread(IthCreateThread(InjectThread, aProcesses[i]));
				WaitForSingleObject(hThread.get(), 0);
			}
		}
	}
	return 0;
}

DWORD SaveProcessProfile(DWORD pid)
{
	const ProcessRecord* pr = man->GetProcessRecord(pid);
	if (pr == NULL)
		return 0;
	std::wstring path = GetProcessPath(pid);
	if (path.empty())
		return 0;
	Profile* pf = pfman->GetProfile(pid);
	if (pf != NULL)
		pf->Clear();
	else
		pf = pfman->AddProfile(path, pid);
	AddHooksToProfile(*pf, *pr);
	AddThreadsToProfile(*pf, *pr, pid);
	return 0;
}

void AddHooksToProfile(Profile& pf, const ProcessRecord& pr)
{
	WaitForSingleObject(pr.hookman_mutex, 0);
	auto hooks = (const Hook*)pr.hookman_map;
	for (DWORD i = 0; i < MAX_HOOK; ++i)
	{
		if (hooks[i].Address() == 0)
			continue;
		auto& hook = hooks[i];
		DWORD type = hook.Type();
		if ((type & HOOK_ADDITIONAL) && (type & HOOK_ENGINE) == 0)
		{
			std::unique_ptr<WCHAR[]> name(new WCHAR[hook.NameLength() * 2]);
			if (ReadProcessMemory(pr.process_handle, hook.Name(), name.get(), hook.NameLength() * 2, NULL))
			{
				if (hook.hp.module)
				{
					HookParam hp = hook.hp;
					MakeHookRelative(pr, hp);
					pf.AddHook(hp, name.get());
				}
				else
					pf.AddHook(hook.hp, name.get());
			}
		}
	}
	ReleaseMutex(pr.hookman_mutex);
}

void MakeHookRelative(const ProcessRecord& pr, HookParam& hp)
{
	MEMORY_BASIC_INFORMATION info;
	VirtualQueryEx(pr.process_handle, (LPCVOID)hp.addr, &info, sizeof(info));
	hp.addr -= (DWORD)info.AllocationBase;
	hp.function = 0;
}

void AddThreadsToProfile(Profile& pf, const ProcessRecord& pr, DWORD pid)
{
	man->LockHookman();
	ThreadTable* table = man->Table();
	for (int i = 0; i < table->Used(); ++i)
	{
		TextThread* tt = table->FindThread(i);
		if (tt == NULL || tt->GetThreadParameter()->pid != pid)
			continue;
		//if (tt->Status() & CURRENT_SELECT || tt->Link() || tt->GetComment())
		if (tt->Status() & CURRENT_SELECT || tt->Link())
			AddThreadToProfile(pf, pr, *tt);
	}
	man->UnlockHookman();
}

DWORD AddThreadToProfile(Profile& pf, const ProcessRecord& pr, TextThread& thread)
{
	const ThreadParameter* tp = thread.GetThreadParameter();
	std::wstring hook_name = GetHookNameByAddress(pr, tp->hook);
	if (hook_name.empty())
		return -1;
	auto thread_profile = new ThreadProfile(hook_name, tp->retn, tp->spl, 0, 0,
		THREAD_MASK_RETN | THREAD_MASK_SPLIT, L"");
	DWORD threads_size = pf.Threads().size();
	int thread_profile_index = pf.AddThread(thread_ptr(thread_profile));
	if (thread_profile_index == threads_size) // new thread
	{
		WORD iw = thread_profile_index & 0xFFFF;
		if (thread.Status() & CURRENT_SELECT)
			pf.SelectedIndex() = iw;
		if (thread.Link())
		{
			WORD to_index = AddThreadToProfile(pf, pr, *(thread.Link())) & 0xFFFF;
			if (iw >= 0)
				pf.AddLink(link_ptr(new LinkProfile(iw, to_index)));
		}
	}
	return thread_profile_index; // in case more than one thread links to the same thread.
}

std::wstring GetHookNameByAddress(const ProcessRecord& pr, DWORD hook_address)
{
	std::wstring hook_name;
	WaitForSingleObject(pr.hookman_mutex, 0);
	auto hooks = (const Hook*)pr.hookman_map;
	for (int i = 0; i < MAX_HOOK; ++i)
	{
		auto& hook = hooks[i];
		if (hook.Address() == hook_address)
		{
			std::unique_ptr<WCHAR[]> name(new WCHAR[hook.NameLength() * 2]);
			if (ReadProcessMemory(pr.process_handle, hooks[i].Name(), name.get(), hook.NameLength() * 2, NULL))
				hook_name = name.get();
			break;
		}
	}
	ReleaseMutex(pr.hookman_mutex);
	return hook_name;
}

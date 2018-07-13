#include "ProfileManager.h"
#include "profile/Profile.h"
#include "host/host.h"
#include "host/hookman.h"
#include "vnrhook/include/types.h"
#include "vnrhook/include/const.h"
#include "utility.h"
#include "profile/misc.h"

extern HookManager* man; // main.cpp
ProfileManager* pfman;

ProfileManager::ProfileManager()
{
	LoadProfiles();
}

ProfileManager::~ProfileManager()
{
	SaveProfiles();
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

bool ProfileManager::CreateProfile(pugi::xml_node game)
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
    CSLock lock(cs);
    auto& oldProfile = profile_tree[path.value()];
    if (!oldProfile)
        oldProfile.swap(profile_ptr(pf));
    return true;
}

Profile* ProfileManager::CreateProfile(DWORD pid)
{
	CSLock lock(cs);
	auto path = GetProcessPath(pid);
	auto& pf = profile_tree[path];
	if (!pf)
	{
		std::wstring title = GetProcessTitle(pid);
		pf.reset(new Profile(title));
	}
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

void ProfileManager::LoadProfiles()
{
	pugi::xml_document doc;
	UniqueHandle hFile(IthCreateFile(L"NextHooker_Profile.xml", GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING));
	if (hFile.get() == INVALID_HANDLE_VALUE)
		return;
	DWORD size = GetFileSize(hFile.get(), NULL);
	std::unique_ptr<char[]> buffer(new char[size]);
	ReadFile(hFile.get(), buffer.get(), size, &size, NULL);
	auto result = doc.load_buffer(buffer.get(), size);
	if (!result)
		return;
	auto root = doc.root().child(L"NextHookerProfile");
	if (!root)
		return;
	for (auto game = root.begin(); game != root.end(); ++game)
		CreateProfile(*game);
}

void ProfileManager::SaveProfiles()
{
	pugi::xml_document doc;
	auto root = doc.append_child(L"NextHookerProfile");
	for (auto it = profile_tree.begin(); it != profile_tree.end(); ++it) {
		auto& path = it->first;
		auto& profile = it->second;
		WriteProfileXml(path, *profile, root);
	}
	UniqueHandle hFile(IthCreateFile(L"NextHooker_Profile.xml", GENERIC_WRITE, 0, CREATE_ALWAYS));
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

Profile* ProfileManager::GetProfile(const std::wstring& path)
{
	if (path.empty())
		return nullptr;
	auto it = profile_tree.find(path);
	if (it == profile_tree.end())
		return nullptr;
	return it->second.get();
}

bool ProfileManager::HasProfile(const std::wstring& path)
{
	return profile_tree.find(path) != profile_tree.end();
}

DWORD ProfileManager::CountProfiles()
{
	return profile_tree.size();
}

DWORD SaveProcessProfile(DWORD pid)
{
	std::wstring path = GetProcessPath(pid);
	if (path.empty())
		return 0;
	pugi::xml_document doc;
	pugi::xml_node profile_node = doc.append_child(L"Profile");
	man->GetProfile(pid, profile_node);
	Profile* pf = pfman->GetProfile(pid);
	if (pf != NULL)
		pf->Clear();
	else
		pf = pfman->CreateProfile(pid);
	pf->XmlReadProfile(profile_node);
	return 0;
}

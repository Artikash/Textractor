#pragma once
#include "ITH.h"
#include "utility.h" // UniqueHandle, CriticalSection

class Profile;

class ProfileManager
{
public:
	ProfileManager();
	~ProfileManager();
	Profile* AddProfile(const std::wstring& path, DWORD pid);
	void DeleteProfile(const std::wstring& path);
	void LoadProfile();
	void SaveProfile();
	void FindProfileAndUpdateHookAddresses(DWORD pid, const std::wstring& path);
	bool HasProfile(const std::wstring& path);
	Profile* GetProfile(DWORD pid);
	DWORD ProfileCount();
private:
	typedef std::unique_ptr<Profile> profile_ptr;
	typedef std::map<std::wstring, profile_ptr> profile_map;
	
	ProfileManager(const ProfileManager&);
	ProfileManager operator=(const ProfileManager&);

	bool AddProfile(pugi::xml_node game);
	Profile* AddProfile(const std::wstring& path, profile_ptr new_profile);
	void WriteProfileXml(const std::wstring& path, Profile& pf, pugi::xml_node doc);
	// locate profile with executable path
	profile_map profile_tree;
	CriticalSection cs;
	UniqueHandle hMonitorThread;
};

#pragma once

#include "ITH.h"
#include "utility.h" // UniqueHandle, CriticalSection

class Profile;

class ProfileManager
{
public:
	ProfileManager();
	~ProfileManager();
	Profile* CreateProfile(DWORD pid);
    Profile* GetProfile(DWORD pid);
    Profile* GetProfile(const std::wstring& path);
    void LoadProfiles();
    void SaveProfiles();
    void DeleteProfile(const std::wstring& path);
	void UpdateHookAddresses(DWORD pid);
	bool HasProfile(const std::wstring& path);
private:
	typedef std::unique_ptr<Profile> profile_ptr;
	typedef std::map<std::wstring, profile_ptr> profile_map;
	
	ProfileManager(const ProfileManager&);
	ProfileManager operator=(const ProfileManager&);

    DWORD CountProfiles();
    bool CreateProfile(pugi::xml_node game);
	void WriteProfileXml(const std::wstring& path, Profile& pf, pugi::xml_node doc);
	// locate profile with executable path
	profile_map profile_tree;
	CriticalSection cs;
	UniqueHandle hMonitorThread;
};

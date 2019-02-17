#pragma once

// vnrhook/defs.h
// 8/23/2013 jichi

#include "common.h"

// Pipes

constexpr auto HOOK_PIPE = L"\\\\.\\pipe\\TEXTRACTOR_HOOK";
constexpr auto HOST_PIPE = L"\\\\.\\pipe\\TEXTRACTOR_HOST";

// Sections

constexpr auto ITH_SECTION_ = L"VNR_SECTION_"; // _%d

// Mutexes

constexpr auto ITH_HOOKMAN_MUTEX_ = L"VNR_HOOKMAN_"; // ITH_HOOKMAN_%d
constexpr auto CONNECTING_MUTEX = L"TEXTRACTOR_CONNECTING_PIPES";

// Events

constexpr auto PIPE_AVAILABLE_EVENT = L"TEXTRACTOR_PIPE_AVAILABLE";

// Files

constexpr auto ITH_DLL = L"vnrhook"; // .dll but LoadLibrary automatically adds that
constexpr auto CONFIG_FILE = u8"Textractor.ini";
constexpr auto HOOK_SAVE_FILE = u8"SavedHooks.txt";
constexpr auto GAME_SAVE_FILE = u8"SavedGames.txt";
constexpr auto EXTEN_SAVE_FILE = u8"SavedExtensions.txt";
constexpr auto REPLACE_SAVE_FILE = u8"SavedReplacements.txt";

// Misc

constexpr auto DEFAULT_EXTENSIONS = u8"Remove Repetition>Lua>Copy to Clipboard>Bing Translate>Extra Window>Extra Newlines";

inline SECURITY_ATTRIBUTES allAccess = std::invoke([] // allows non-admin processes to access kernel objects made by admin processes
{
	static SECURITY_DESCRIPTOR sd = {};
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
	return SECURITY_ATTRIBUTES{ sizeof(SECURITY_ATTRIBUTES), &sd, FALSE };
});

// Functions

template <typename... Args>
inline void FORMAT_MESSAGE(const char* format, Args... args)
{
	char buffer[250] = {};
	sprintf_s<250>(buffer, format, args...);
	MessageBoxA(NULL, buffer, "Textractor Message", MB_OK);
}

#ifdef _DEBUG
#define TEST(...) inline auto TEST__RUNNER__DUMMY = (CloseHandle(CreateThread(nullptr, 0, [](auto) { __VA_ARGS__; return 0UL; }, NULL, 0, nullptr)), 0); 
#else
#define TEST(...)
#endif

// EOF

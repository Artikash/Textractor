#pragma once

// vnrhook/defs.h
// 8/23/2013 jichi

#include "common.h"

// Pipes

constexpr auto HOOK_PIPE = L"\\\\.\\pipe\\TEXTRACTOR_HOOK";
constexpr auto HOST_PIPE = L"\\\\.\\pipe\\TEXTRACTOR_HOST";

// Sections

constexpr auto ITH_SECTION_ = L"VNR_SECTION_"; // _%d

// Mutex

constexpr auto ITH_HOOKMAN_MUTEX_ = L"VNR_HOOKMAN_"; // ITH_HOOKMAN_%d

// Files

constexpr auto ITH_DLL = L"vnrhook"; // .dll but LoadLibrary automatically adds that
constexpr auto CONFIG_FILE = u8"Textractor.ini";
constexpr auto HOOK_SAVE_FILE = u8"SavedHooks.txt";
constexpr auto EXTEN_SAVE_FILE = u8"Extensions.txt";

// Functions

template <typename... Ts>
inline void FORMAT_MESSAGE(const char* format, Ts ...args)
{
	char buffer[250] = {};
	sprintf_s<250>(buffer, format, args...);
	MessageBoxA(NULL, buffer, "Textractor Message", MB_OK);
}

// EOF

#pragma once

// vnrhook/defs.h
// 8/23/2013 jichi

constexpr auto ITH_DLL = L"vnrhook";

// Pipes

constexpr auto HOOK_PIPE = L"\\\\.\\pipe\\TEXTRACTOR_HOOK";
constexpr auto HOST_PIPE = L"\\\\.\\pipe\\TEXTRACTOR_HOST";

// Sections

constexpr auto ITH_SECTION_ = L"VNR_SECTION_"; // _%d

// Mutex

constexpr auto ITH_HOOKMAN_MUTEX_ = L"VNR_HOOKMAN_"; // ITH_HOOKMAN_%d

// Files

constexpr auto CONFIG_FILE = u8"Textractor.ini";
constexpr auto HOOK_SAVE_FILE = u8"SavedHooks.txt";
constexpr auto EXTEN_SAVE_FILE = u8"Extensions.txt";

// EOF

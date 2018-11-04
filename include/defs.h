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

// Settings

constexpr auto WINDOW = u8"Window";
constexpr auto DEFAULT_CODEPAGE = u8"Default_Codepage";
constexpr auto FLUSH_DELAY = u8"Flush_Delay";
constexpr auto MAX_BUFFER_SIZE = u8"Max_Buffer_Size";

// EOF

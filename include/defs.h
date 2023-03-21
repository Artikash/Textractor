#pragma once

// texthook/defs.h
// 8/23/2013 jichi

// Pipes

constexpr auto HOOK_PIPE = L"\\\\.\\pipe\\EXTRA_TEXTRACTOR_HOOK";
constexpr auto HOST_PIPE = L"\\\\.\\pipe\\EXTRA_TEXTRACTOR_HOST";

// Sections

constexpr auto ITH_SECTION_ = L"EXTRA_VNR_SECTION_"; // _%d

// Mutexes

constexpr auto ITH_HOOKMAN_MUTEX_ = L"EXTRA_VNR_HOOKMAN_"; // ITH_HOOKMAN_%d
constexpr auto CONNECTING_MUTEX = L"EXTRA_TEXTRACTOR_CONNECTING_PIPES";

// Events

constexpr auto PIPE_AVAILABLE_EVENT = L"EXTRA_TEXTRACTOR_PIPE_AVAILABLE";

// Files

constexpr auto ITH_DLL = L"texthook_extra"; // .dll but LoadLibrary automatically adds that
constexpr auto& GAME_CONFIG_FILE = L"TextractorConfig.txt";

// EOF

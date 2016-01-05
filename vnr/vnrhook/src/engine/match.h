#pragma once

// engine/match.h
// 8/23/2013 jichi
// TODO: Clean up the interface to match game engines.
// Split the engine match logic out of hooks.
// Modify the game hook to allow replace functions for arbitary purpose
// instead of just extracting text.

#include <windows.h>

namespace Engine {

// jichi 10/21/2014: Return whether found the engine
void hijack();
void terminate();

// jichi 10/21/2014: Return 0 if failed
DWORD InsertDynamicHook(LPVOID addr, DWORD frame, DWORD stack);

} // namespace Engine

// EOF

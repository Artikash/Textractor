#pragma once

// engine/match.h
// 8/23/2013 jichi
// TODO: Clean up the interface to match game engines.
// Split the engine match logic out of hooks.
// Modify the game hook to allow replace functions for arbitary purpose
// instead of just extracting text.

#include "config.h"

namespace Engine {

void match(LPVOID lpThreadParameter);

// jichi 10/21/2014: Return whether found the engine
bool IdentifyEngine();

// jichi 10/21/2014: Return 0 if failed
DWORD InsertDynamicHook(LPVOID addr, DWORD frame, DWORD stack);

} // namespace Engine

// EOF

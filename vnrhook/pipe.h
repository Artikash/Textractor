#pragma once

#include "common.h"
#include "types.h"

void CreatePipe();
void NotifyHookRemove(uint64_t addr);
void ConsoleOutput(LPCSTR text); // jichi 12/25/2013: Used to return length of sent text

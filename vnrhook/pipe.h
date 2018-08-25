#pragma once

#include "common.h"
#include "types.h"

void CreatePipe();
void NotifyHookRemove(unsigned __int64 addr);
void ConsoleOutput(LPCSTR text); // jichi 12/25/2013: Used to return length of sent text

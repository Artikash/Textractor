#pragma once

// pchooks.h
// 8/1/2014 jichi

#include "config.h"

namespace PcHooks {

void hookGDIFunctions();
void hookLstrFunctions();
void hookWcharFunctions();

} // namespace PcHooks

// EOF

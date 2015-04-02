#pragma once

// engine/hookdefs.h
// 7/20/2014 jichi

#include "config.h"

// For HookParam user flags
enum HookParamFlag : unsigned long {
  HPF_Null             = 0      // never used
  , HPF_IgnoreSameAddress = 1   // ignore the last same text address
};

// EOF

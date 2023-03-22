// match.cc
// 8/9/2013 jichi
// Branch: ITH_Engine/engine.cpp, revision 133

#include "engine/match.h"
#include "engine/engine.h"
#include "engine/native/pchooks.h"
#include "util/util.h"
#include "main.h"
#include "ithsys/ithsys.h"

//#define ConsoleOutput(...)  (void)0     // jichi 8/18/2013: I don't need ConsoleOutput

enum { MAX_REL_ADDR = 0x200000 }; // jichi 8/18/2013: maximum relative address

// - Methods -

namespace Engine { 


bool UnsafeDetermineEngineType()
{
	return false;
}

} // namespace Engine

// - API -

// EOF

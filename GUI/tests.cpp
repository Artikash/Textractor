#include "extensions.h"
#include "misc.h"

static int TESTS = []
{
	assert(ParseCode("/HQN936#-c*C:C*1C@4AA:gdi.dll:GetTextOutA"));
	assert(ParseCode("/HB4@0"));
	assert(ParseCode("/RS*10@44"));
	assert(!ParseCode("HQ@4"));
	assert(!ParseCode("/RW@44"));
	assert(!ParseCode("/HWG@33"));

	return 0;
}();
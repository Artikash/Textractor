#include "hostsignaller.h"
#include "extensions.h"

void HostSignaller::Initialize()
{
	Host::RegisterProcessAttachCallback([&](DWORD pid){ emit AddProcess(pid); });
	Host::RegisterProcessDetachCallback([&](DWORD pid){ emit RemoveProcess(pid); });
	Host::RegisterThreadCreateCallback([&](TextThread* thread) { emit AddThread(thread); });
	Host::RegisterThreadRemoveCallback([&](TextThread* thread){ emit RemoveThread(thread); });
}

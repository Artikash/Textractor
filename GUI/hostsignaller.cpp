#include "hostsignaller.h"
#include "extensions.h"

void HostSignaller::Initialize()
{
	Host::RegisterProcessAttachCallback([&](DWORD pid){ emit AddProcess(pid); });
	Host::RegisterProcessDetachCallback([&](DWORD pid){ emit RemoveProcess(pid); });
	Host::RegisterThreadCreateCallback([&](TextThread* thread)
	{
		emit AddThread(thread);
		thread->RegisterOutputCallBack([&](TextThread* thread, std::wstring output)
		{
			output = DispatchSentenceToExtensions(output,
			{
				{ "current select", ttCombo->currentText().split(":")[0].toInt() == thread->Number() ? 1 : 0 }
			});
			emit ThreadOutput(thread, QString::fromWCharArray(output.c_str()));
			return output;
		});
	});
	Host::RegisterThreadRemoveCallback([&](TextThread* thread){ emit RemoveThread(thread); });
}

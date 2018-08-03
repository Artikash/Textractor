#ifndef HOSTSIGNALLER_H
#define HOSTSIGNALLER_H

#include <QObject>
#include <Windows.h>
#include "../host/host.h"

// Artikash 7/24/2018: This class is a workaround for the fact that Qt only lets me manipulate the GUI in the main thread.
class HostSignaller : public QObject
{
	Q_OBJECT

public:
	void Initialize();

signals:
	void AddProcess(unsigned int processId);
	void RemoveProcess(unsigned int processId);
	void AddThread(TextThread* thread);
	void RemoveThread(TextThread* thread);
};

#endif // HOSTSIGNALLER_H

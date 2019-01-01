#pragma once

#include "qtcommon.h"
#include "host/host.h"

namespace Ui
{
	class MainWindow;
}

class MainWindow : public QMainWindow
{
public:
	explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow();

private:
	void closeEvent(QCloseEvent*) override;
	void ProcessConnected(DWORD processId);
	void ProcessDisconnected(DWORD processId);
	void ThreadAdded(TextThread* thread);
	void ThreadRemoved(TextThread* thread);
	bool SentenceReceived(TextThread* thread, std::wstring& sentence);
	QString TextThreadString(TextThread* thread);
	ThreadParam ParseTextThreadString(QString ttString);
	DWORD GetSelectedProcessId();
	std::unordered_map<const char*, int64_t> GetMiscInfo(TextThread* thread);
	void AttachProcess();
	void DetachProcess();
	void AddHook();
	void SaveHooks();
	void Settings();
	void Extensions();
	void ViewThread(int index);

	Ui::MainWindow* ui;
	QWidget* extenWindow;
};

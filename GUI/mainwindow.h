#pragma once

#include "qtcommon.h"
#include "extenwindow.h"
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
	inline static constexpr auto HOOK_SAVE_FILE = u8"SavedHooks.txt";
	inline static constexpr auto GAME_SAVE_FILE = u8"SavedGames.txt";

	inline static thread_local bool ok = false;

	void closeEvent(QCloseEvent*) override;
	bool isProcessSaved(const QString& process);
	void ProcessConnected(DWORD processId);
	void ProcessDisconnected(DWORD processId);
	void ThreadAdded(TextThread& thread);
	void ThreadRemoved(TextThread& thread);
	bool SentenceReceived(TextThread& thread, std::wstring& sentence);
	QString TextThreadString(TextThread& thread);
	ThreadParam ParseTextThreadString(QString ttString);
	DWORD GetSelectedProcessId();
	std::array<InfoForExtension, 10> GetMiscInfo(TextThread& thread);
	void AttachProcess();
	void LaunchProcess();
	void DetachProcess();
	void AddHook();
	void SaveHooks();
	void Settings();
	void Extensions();
	void ViewThread(int index);

	Ui::MainWindow* ui;
	QWidget* extenWindow;
	std::pair<uint64_t, uint64_t> savedThreadCtx;
	wchar_t savedThreadCode[1000];
	std::atomic<TextThread*> current;
};

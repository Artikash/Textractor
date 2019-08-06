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
	void ProcessConnected(DWORD processId);
	void ProcessDisconnected(DWORD processId);
	void ThreadAdded(TextThread& thread);
	void ThreadRemoved(TextThread& thread);
	bool SentenceReceived(TextThread& thread, std::wstring& sentence);
	void OutputContextMenu(QPoint point);
	QString TextThreadString(TextThread& thread);
	ThreadParam ParseTextThreadString(QString ttString);
	DWORD GetSelectedProcessId();
	std::array<InfoForExtension, 10> GetMiscInfo(TextThread& thread);
	std::optional<std::wstring> UserSelectedProcess();
	void AttachProcess();
	void LaunchProcess();
	void DetachProcess();
	void ForgetProcess();
	void AddHook();
	void AddHook(QString hook);
	void RemoveHooks();
	void SaveHooks();
	void FindHooks();
	void Settings();
	void Extensions();
	void ViewThread(int index);
	void SetOutputFont(QString font);

	Ui::MainWindow* ui;
	ExtenWindow* extenWindow;
	std::unordered_set<DWORD> alreadyAttached;
	bool autoAttach = false, autoAttachSavedOnly = true;
	uint64_t savedThreadCtx = 0, savedThreadCtx2 = 0;
	wchar_t savedThreadCode[1000] = {};
	TextThread* current = nullptr;
};

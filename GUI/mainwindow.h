#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "qtcommon.h"
#include "host/host.h"
#include "defs.h"
#include <QPlainTextEdit>
#include <QComboBox>
#include <QSettings>

namespace Ui
{
	class MainWindow;
}

class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow();

private slots:
	void on_attachButton_clicked();
	void on_detachButton_clicked();
	void on_unhookButton_clicked();
	void on_hookButton_clicked();
	void on_saveButton_clicked();
	void on_setButton_clicked();
	void on_extenButton_clicked();
	void on_ttCombo_activated(int index);

private:
	void InvokeOnMainThread(std::function<void()>&& f);
	void ProcessConnected(DWORD processId);
	void ProcessDisconnected(DWORD processId);
	void ThreadAdded(TextThread* thread);
	void ThreadRemoved(TextThread* thread);
	bool SentenceReceived(TextThread* thread, std::wstring& sentence);
	QString TextThreadString(TextThread* thread);
	ThreadParam ParseTextThreadString(QString ttString);
	DWORD GetSelectedProcessId();
	std::unordered_map<std::string, int64_t> GetMiscInfo(TextThread* thread);
	QVector<HookParam> GetAllHooks(DWORD processId);
	void closeEvent(QCloseEvent*);

	Ui::MainWindow* ui;
	QSettings settings = QSettings(CONFIG_FILE, QSettings::IniFormat);
	QComboBox* processCombo;
	QComboBox* ttCombo;
	QPlainTextEdit* textOutput;
	QWidget* extenWindow;
};

#endif // MAINWINDOW_H

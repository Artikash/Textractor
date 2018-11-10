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

Q_DECLARE_METATYPE(std::shared_ptr<TextThread>);

class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow();

signals:
	void SigAddProcess(unsigned processId);
	void SigRemoveProcess(unsigned processId);
	void SigAddThread(std::shared_ptr<TextThread>);
	void SigRemoveThread(std::shared_ptr<TextThread>);
	void SigThreadOutput(QString threadString, QString output);

private slots:
	void AddProcess(unsigned processId);
	void RemoveProcess(unsigned processId);
	void AddThread(std::shared_ptr<TextThread> thread);
	void RemoveThread(std::shared_ptr<TextThread> thread);
	void ThreadOutput(QString threadString, QString output); // this function doesn't take TextThread* because it might be destroyed on pipe thread
	void on_attachButton_clicked();
	void on_detachButton_clicked();
	void on_unhookButton_clicked();
	void on_hookButton_clicked();
	void on_saveButton_clicked();
	void on_setButton_clicked();
	void on_extenButton_clicked();
	void on_ttCombo_activated(int index);

private:
	bool ProcessThreadOutput(TextThread* thread, std::wstring& output);
	QString TextThreadString(TextThread* thread);
	ThreadParam ParseTextThreadString(QString textThreadString);
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

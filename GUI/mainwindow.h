#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "qtcommon.h"
#include "host/host.h"
#include <QMainWindow>
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

signals:
	void SigAddProcess(unsigned processId);
	void SigRemoveProcess(unsigned processId);
	void SigAddThread(TextThread* thread);
	void SigRemoveThread(TextThread* thread);
	void SigThreadOutput(TextThread* thread, QString output);

private slots:
	void AddProcess(unsigned processId);
	void RemoveProcess(unsigned processId);
	void AddThread(TextThread* thread);
	void RemoveThread(TextThread* thread);
	void ThreadOutput(TextThread* thread, QString output);
	void on_attachButton_clicked();
	void on_detachButton_clicked();
	void on_ttCombo_activated(int index);
	void on_unhookButton_clicked();
	void on_hookButton_clicked();
	void on_saveButton_clicked();
	void on_addExtenButton_clicked();
	void on_moveExtenButton_clicked();
	void on_rmvExtenButton_clicked();

private:
	bool ProcessThreadOutput(TextThread* thread, std::wstring& output);
	QString TextThreadString(TextThread* thread);
	ThreadParam ParseTextThreadString(QString textThreadString);
	DWORD GetSelectedProcessId();
	void ReloadExtensions();
	std::unordered_map<std::string, int64_t> GetInfoForExtensions(TextThread* thread);
	QVector<HookParam> GetAllHooks(DWORD processId);

	Ui::MainWindow* ui;
	QSettings settings = QSettings("Textractor.ini", QSettings::IniFormat);
	QComboBox* processCombo;
	QComboBox* ttCombo;
	QComboBox* extenCombo;
	QPlainTextEdit* textOutput;
};

#endif // MAINWINDOW_H

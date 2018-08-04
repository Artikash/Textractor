#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <Windows.h>
#include <QVector>
#include <unordered_map>
#include <string>
#include "../host/host.h"
#include "hostsignaller.h"

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
	void ThreadOutputReceived(TextThread* thread, QString output);

private slots:
	void AddProcess(unsigned int processId);
	void RemoveProcess(unsigned int processId);
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
	void on_rmvExtenButton_clicked();

private:
	std::unordered_map<std::string, int> GetInfoForExtensions(TextThread* thread);
	QVector<HookParam> GetAllHooks(DWORD processId);

	Ui::MainWindow *ui;
	HostSignaller* hostSignaller;
};

#endif // MAINWINDOW_H

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QCoreApplication>
#include "QTextBrowser"
#include "QMessageBox"
#include "QComboBox"
#include "QLineEdit"
#include "QInputDialog"
#include <QCursor>
#include <Qt>
#include <unordered_set>
#include <Windows.h>
#include <qdebug.h>
#include <Psapi.h>
#include "misc.h"

QMainWindow* mainWindow;
QComboBox* processCombo;
QComboBox* ttCombo;
QTextBrowser* textOutput;

QString ProcessString(DWORD processId)
{
	return QString("%1: %2").arg(QString::number(processId), GetModuleName(processId));
}

QString TextThreadString(TextThread* thread)
{
	ThreadParameter tp = thread->GetThreadParameter();
	return QString("%1:%2:%3:%4:%5: ").arg(
		QString::number(thread->Number()),
		QString::number(tp.pid),
		QString::number(tp.hook, 16),
		QString::number(tp.retn, 16),
		QString::number(tp.spl, 16)
	).toUpper();
}

MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow),
	hostSignaller(new HostSignaller)
{
	ui->setupUi(this);
	mainWindow = this;
	processCombo = mainWindow->findChild<QComboBox*>("processCombo");
	ttCombo = mainWindow->findChild<QComboBox*>("ttCombo");
	textOutput = mainWindow->findChild<QTextBrowser*>("textOutput");

	hostSignaller->Initialize();
	connect(hostSignaller, &HostSignaller::AddProcess, this, &MainWindow::AddProcess);
	connect(hostSignaller, &HostSignaller::RemoveProcess, this, &MainWindow::RemoveProcess);
	connect(hostSignaller, &HostSignaller::AddThread, this, &MainWindow::AddThread);
	connect(hostSignaller, &HostSignaller::RemoveThread, this, &MainWindow::RemoveThread);
	connect(hostSignaller, &HostSignaller::ThreadOutput, this, &MainWindow::ThreadOutput);
	Host::Open();
}

MainWindow::~MainWindow()
{
	delete ui;
}

void MainWindow::AddProcess(unsigned int processId)
{
	processCombo->addItem(ProcessString(processId));
}

void MainWindow::RemoveProcess(unsigned int processId)
{
	processCombo->removeItem(processCombo->findText(QString::number(processId) + ":", Qt::MatchStartsWith));
}

void MainWindow::AddThread(TextThread* thread)
{
	ttCombo->addItem(
		TextThreadString(thread) +
		QString::fromWCharArray(Host::GetHookName(thread->GetThreadParameter().pid, thread->GetThreadParameter().hook).c_str()) +
		" (" +
		GenerateHCode(Host::GetHookParam(thread->GetThreadParameter().pid, thread->GetThreadParameter().hook), thread->GetThreadParameter().pid) +
		")"
	);
}

void MainWindow::RemoveThread(TextThread* thread)
{
	int threadIndex = ttCombo->findText(QString::number(thread->Number()) + ":", Qt::MatchStartsWith);
	ttCombo->removeItem(threadIndex);
	if (threadIndex == ttCombo->currentIndex())
	{
		ttCombo->setCurrentIndex(0);
		on_ttCombo_activated(0);
	}
}

void MainWindow::ThreadOutput(TextThread* thread, QString output)
{
	if (ttCombo->currentText().startsWith(TextThreadString(thread)))
	{
		textOutput->moveCursor(QTextCursor::End);
		textOutput->insertPlainText(output);
		textOutput->moveCursor(QTextCursor::End);
	}
}

QVector<HookParam> MainWindow::GetAllHooks(DWORD processId)
{
	std::unordered_set<DWORD> addresses;
	QVector<HookParam> hooks;
	for (int i = 0; i < ttCombo->count(); ++i)
		if (ttCombo->itemText(i).split(":")[1].toInt() == processId &&
				!addresses.count(ttCombo->itemText(i).split(":")[2].toInt(nullptr, 16)))
		{
			addresses.insert(ttCombo->itemText(i).split(":")[2].toInt(nullptr, 16));
			hooks.push_back(Host::GetHookParam(ttCombo->itemText(i).split(":")[1].toInt(), ttCombo->itemText(i).split(":")[2].toInt(nullptr, 16)));
		}
	return hooks;
}

void MainWindow::on_attachButton_clicked()
{
	bool ok;
	int processId = QInputDialog::getInt(this, "Attach Process", "Process ID?\r\nYou can find this under Task Manager -> Details", 0, 0, 100000, 1, &ok);
	if (ok) Host::InjectProcess(processId);
}

void MainWindow::on_detachButton_clicked()
{
	Host::DetachProcess(processCombo->currentText().split(":")[0].toInt());
}

void MainWindow::on_hookButton_clicked()
{
	bool ok;
	QString hookCode = QInputDialog::getText(this, "Add Hook",
		"Enter hook code\r\n/H{A|B|W|S|Q}[N][data_offset[*drdo]][:sub_offset[*drso]]@addr[:module]",
		QLineEdit::Normal, "/H", &ok
	);
	if (ok) Host::InsertHook(processCombo->currentText().split(":")[0].toInt(), ParseHCode(hookCode, processCombo->currentText().split(":")[0].toInt()));
}

void MainWindow::on_unhookButton_clicked()
{
	QVector<HookParam> hooks = GetAllHooks(processCombo->currentText().split(":")[0].toInt());
	QStringList hookList;
	for (auto i : hooks) hookList.push_back(
				QString::fromWCharArray(Host::GetHookName(processCombo->currentText().split(":")[0].toInt(), i.address).c_str()) +
				": " +
				GenerateHCode(i, processCombo->currentText().split(":")[0].toInt())
			);
	bool ok;
	QString hook = QInputDialog::getItem(this, "Unhook", "Which hook to remove?", hookList, 0, false, &ok);
	if (ok) Host::RemoveHook(processCombo->currentText().split(":")[0].toInt(), hooks.at(hookList.indexOf(hook)).address);
}

void MainWindow::on_ttCombo_activated(int index)
{
	textOutput->setText(QString::fromWCharArray(Host::GetThread(ttCombo->itemText(index).split(":")[0].toInt())->GetStore().c_str()));
	textOutput->moveCursor(QTextCursor::End);
}

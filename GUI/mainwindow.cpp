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
#include <QPlainTextEdit>
#include <QDateTime>
#include <QFileDialog>
#include <unordered_set>
#include <map>
#include <unordered_map>
#include <Windows.h>
#include <qdebug.h>
#include <Psapi.h>
#include "extensions.h"
#include "../vnrhook/include/const.h"
#include "misc.h"

QString ProcessString(DWORD processId)
{
	return QString("%1: %2").arg(QString::number(processId), GetModuleName(processId));
}

QString TextThreadString(TextThread* thread)
{
	ThreadParameter tp = thread->GetThreadParameter();
	return QString("%1:0x%2:0x%3:0x%4: ").arg(
		QString::number(tp.pid).toUpper(),
		QString::number(tp.hook, 16).toUpper(),
		QString::number(tp.retn, 16).toUpper(),
		QString::number(tp.spl, 16).toUpper()
	);
}

ThreadParameter ParseTextThreadString(QString textThreadString)
{
	QStringList threadParam = textThreadString.split(":");
	return { threadParam[0].toUInt(), threadParam[1].toULongLong(nullptr, 0), threadParam[2].toULongLong(nullptr, 0), threadParam[3].toULongLong(nullptr, 0) };
}

MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow)
{
	ui->setupUi(this);

	QFile settings("NHWindow");
	settings.open(QIODevice::ReadOnly);
	QDataStream reader(&settings);
	QRect rect = QRect();
	reader >> rect;
	if (rect.bottom()) this->setGeometry(rect);

	processCombo = findChild<QComboBox*>("processCombo");
	ttCombo = findChild<QComboBox*>("ttCombo");
	extenCombo = findChild<QComboBox*>("extenCombo");
	textOutput = findChild<QPlainTextEdit*>("textOutput");

	connect(this, &MainWindow::SigAddProcess, this, &MainWindow::AddProcess);
	connect(this, &MainWindow::SigRemoveProcess, this, &MainWindow::RemoveProcess);
	connect(this, &MainWindow::SigAddThread, this, &MainWindow::AddThread);
	connect(this, &MainWindow::SigRemoveThread, this, &MainWindow::RemoveThread);
	connect(this, &MainWindow::SigThreadOutput, this, &MainWindow::ThreadOutput);
	Host::Start(
		[&](DWORD processId) { emit SigAddProcess(processId); },
		[&](DWORD processId) { emit SigRemoveProcess(processId); },
		[&](TextThread* thread) { emit SigAddThread(thread); },
		[&](TextThread* thread) { emit SigRemoveThread(thread); }
	);

	ReloadExtensions();
	Host::AddConsoleOutput(L"NextHooker beta v2.1.3 by Artikash\r\nSource code and more information available under GPLv3 at https://github.com/Artikash/NextHooker");
}

MainWindow::~MainWindow()
{
	QFile settings("NHWindow");
	settings.open(QIODevice::ReadWrite | QIODevice::Truncate);
	QDataStream writer(&settings);
	writer << this->geometry();
	Host::Close();
	delete ui;
}

void MainWindow::AddProcess(unsigned int processId)
{
	processCombo->addItem(ProcessString(processId));
	QFile file("SavedHooks.txt");
	if (!file.open(QIODevice::ReadOnly)) return;
	QString processName = GetFullModuleName(processId);
	QString allData = file.readAll();
	QStringList allProcesses = allData.split("\r", QString::SkipEmptyParts);
	for (int i = allProcesses.length() - 1; i >= 0; --i)
		if (allProcesses.at(i).contains(processName))
		{
			QStringList hooks = allProcesses.at(i).split(" , ");
			for (int j = 1; j < hooks.length(); ++j)
				Host::InsertHook(processId, ParseCode(hooks.at(j)));
			return;
		}
}

void MainWindow::RemoveProcess(unsigned int processId)
{
	processCombo->removeItem(processCombo->findText(QString::number(processId) + ":", Qt::MatchStartsWith));
}

void MainWindow::AddThread(TextThread* thread)
{
	ttCombo->addItem(
		TextThreadString(thread) +
		QString::fromStdWString(Host::GetHookName(thread->GetThreadParameter().pid, thread->GetThreadParameter().hook)) +
		" (" +
		GenerateCode(Host::GetHookParam(thread->GetThreadParameter()), thread->GetThreadParameter().pid) +
		")"
	);
	thread->RegisterOutputCallBack([&](TextThread* thread, std::wstring output)
	{
		output = DispatchSentenceToExtensions(output, GetInfoForExtensions(thread));
		output += L"\r\n";
		emit SigThreadOutput(thread, QString::fromStdWString(output));
		return output;
	});
}

void MainWindow::RemoveThread(TextThread* thread)
{
	int threadIndex = ttCombo->findText(TextThreadString(thread), Qt::MatchStartsWith);
	if (threadIndex == ttCombo->currentIndex())
	{
		ttCombo->setCurrentIndex(0);
		on_ttCombo_activated(0);
	}
	ttCombo->removeItem(threadIndex);
	delete thread;
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

void MainWindow::ReloadExtensions()
{
	extenCombo->clear();
	std::map<int, QString> extensions = LoadExtensions();
	for (auto i : extensions) extenCombo->addItem(QString::number(i.first) + ": " + i.second);
}

std::unordered_map<std::string, int> MainWindow::GetInfoForExtensions(TextThread* thread)
{
	return 
	{
	{ "current select", (int)ttCombo->currentText().startsWith(TextThreadString(thread)) },
	{ "text number", 0 },
	{ "process id", thread->GetThreadParameter().pid },
	{ "hook address", (int)thread->GetThreadParameter().hook },
	{ "hook address (upper 32 bits)", (int)(thread->GetThreadParameter().hook >> 32) }
	};
}

QVector<HookParam> MainWindow::GetAllHooks(DWORD processId)
{
	std::unordered_set<DWORD> addresses;
	QVector<HookParam> hooks;
	for (int i = 0; i < ttCombo->count(); ++i)
	{
		ThreadParameter tp = ParseTextThreadString(ttCombo->itemText(i));
		if (tp.pid == processId && !addresses.count(tp.hook))
		{
			addresses.insert(tp.hook);
			hooks.push_back(Host::GetHookParam(tp));
		}
	}
	return hooks;
}

DWORD MainWindow::GetSelectedProcessId()
{
	return processCombo->currentText().split(":")[0].toULong();
}

void MainWindow::on_attachButton_clicked()
{
	std::unordered_map<std::wstring, DWORD> allProcesses = GetAllProcesses();
	QStringList processList;
	for (auto i : allProcesses)
		processList.push_back(QString::fromStdWString(i.first));
	processList.sort(Qt::CaseInsensitive);
	bool ok;
	QString process = QInputDialog::getItem(this, "Select Process",
		"If you don't see the process you want to inject, try running with admin rights\r\nYou can just type in the process id if you know it",
		processList, 0, true, &ok);
	if (!ok) return;
	if (process.toInt())
	{
		if (Host::InjectProcess(process.toInt())) return;
	}
	else if (Host::InjectProcess(allProcesses[process.toStdWString()])) return;
	Host::AddConsoleOutput(L"Failed to attach");
}

void MainWindow::on_detachButton_clicked()
{
	Host::DetachProcess(GetSelectedProcessId());
}

void MainWindow::on_hookButton_clicked()
{
	bool ok;
	QString hookCode = QInputDialog::getText(this, "Add Hook", CodeInfoDump, QLineEdit::Normal, "", &ok);
	if (!ok) return;
	HookParam toInsert = ParseCode(hookCode);
	if (toInsert.type == 0 && toInsert.length_offset == 0)
	{
		Host::AddConsoleOutput(L"invalid code");
		return;
	}
	Host::InsertHook(GetSelectedProcessId(), ParseCode(hookCode));
}

void MainWindow::on_unhookButton_clicked()
{
	QVector<HookParam> hooks = GetAllHooks(GetSelectedProcessId());
	QStringList hookList;
	for (auto i : hooks) hookList.push_back(
				QString::fromStdWString(Host::GetHookName(GetSelectedProcessId(), i.address)) +
				": " +
				GenerateCode(i, GetSelectedProcessId())
			);
	bool ok;
	QString hook = QInputDialog::getItem(this, "Unhook", "Which hook to remove?", hookList, 0, false, &ok);
	if (ok) Host::RemoveHook(GetSelectedProcessId(), hooks.at(hookList.indexOf(hook)).address);
}

void MainWindow::on_saveButton_clicked()
{
	QVector<HookParam> hooks = GetAllHooks(GetSelectedProcessId());
	QString hookList = GetFullModuleName(GetSelectedProcessId());
	for (auto i : hooks)
		if (!(i.type & HOOK_ENGINE))
			hookList += " , " + GenerateCode(i, GetSelectedProcessId());
	QFile file("SavedHooks.txt");
	if (!file.open(QIODevice::Append | QIODevice::Text)) return;
	file.write((hookList + "\r\n").toUtf8());
}

void MainWindow::on_ttCombo_activated(int index)
{
	textOutput->setPlainText(QString::fromStdWString(Host::GetThread(ParseTextThreadString(ttCombo->itemText(index)))->GetStore()));
	textOutput->moveCursor(QTextCursor::End);
}

void MainWindow::on_addExtenButton_clicked()
{
	QString extenFileName = QFileDialog::getOpenFileName(this, "Select Extension dll", "C:\\", "Extensions (*.dll)");
	if (!extenFileName.length()) return;
	QString extenName = extenFileName.split("/")[extenFileName.split("/").count() - 1];
	extenName.chop(4);
	QString copyTo = QString::number(extenCombo->itemText(extenCombo->count() - 1).split(":")[0].toInt() + 1) + "_" +
			extenName +
			"_nexthooker_extension.dll";
	QFile::copy(extenFileName, copyTo);
	ReloadExtensions();
}

void MainWindow::on_rmvExtenButton_clicked()
{
	if (extenCombo->currentText().size() == 0) return;
	QString extenFileName = extenCombo->currentText().split(":")[0] + "_" + extenCombo->currentText().split(": ")[1] + "_nexthooker_extension.dll";
	FreeLibrary(GetModuleHandleW(extenFileName.toStdWString().c_str()));
	QFile::remove(extenFileName);
	ReloadExtensions();
}

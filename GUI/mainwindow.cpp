#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "extensions.h"
#include "misc.h"
#include <QCoreApplication>
#include <QInputDialog>
#include <QFileDialog>

MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow)
{
	ui->setupUi(this);
	if (settings.contains("Window")) this->setGeometry(settings.value("Window").toRect());
	// TODO: add GUI for changing these
	if (settings.contains("Flush_Delay")) TextThread::flushDelay = settings.value("Flush_Delay").toInt();
	if (settings.contains("Max_Buffer_Size")) TextThread::maxBufferSize = settings.value("Max_Buffer_Size").toInt();

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
		[&](TextThread* thread) { emit SigRemoveThread(thread); },
		[&](TextThread* thread, std::wstring& output) { return ProcessThreadOutput(thread, output); }
	);

	ReloadExtensions();
	Host::AddConsoleOutput(L"Textractor beta v3.2.2 by Artikash\r\nSource code and more information available under GPLv3 at https://github.com/Artikash/Textractor");
}

MainWindow::~MainWindow()
{
	settings.setValue("Window", this->geometry());
	settings.setValue("Flush_Delay", TextThread::flushDelay);
	settings.setValue("Max_Buffer_Size", TextThread::maxBufferSize);
	settings.sync();
	Host::Close();
	delete ui;
}

void MainWindow::AddProcess(unsigned processId)
{
	processCombo->addItem(QString::number(processId, 16).toUpper() + ": " + GetModuleName(processId));
	QFile file("SavedHooks.txt");
	if (!file.open(QIODevice::ReadOnly)) return;
	QString processName = GetFullModuleName(processId);
	QString allData = file.readAll();
	QStringList allProcesses = allData.split("\r", QString::SkipEmptyParts);
	for (int i = allProcesses.size() - 1; i >= 0; --i)
		if (allProcesses[i].contains(processName))
		{
			QStringList hooks = allProcesses[i].split(" , ");
			for (int j = 1; j < hooks.size(); ++j)
				Host::InsertHook(processId, ParseCode(hooks[j]).value_or(HookParam()));
			return;
		}
}

void MainWindow::RemoveProcess(unsigned processId)
{
	processCombo->removeItem(processCombo->findText(QString::number(processId, 16).toUpper() + ":", Qt::MatchStartsWith));
}

void MainWindow::AddThread(TextThread* thread)
{
	ttCombo->addItem(
		TextThreadString(thread) +
		QString::fromStdWString(thread->name) +
		" (" +
		GenerateCode(Host::GetHookParam(thread->tp), thread->tp.pid) +
		")"
	);
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

bool MainWindow::ProcessThreadOutput(TextThread* thread, std::wstring& output)
{
	if (DispatchSentenceToExtensions(output, GetInfoForExtensions(thread)))
	{
		output += L"\r\n";
		emit SigThreadOutput(thread, QString::fromStdWString(output));
		return true;
	}
	return false;
}

QString MainWindow::TextThreadString(TextThread* thread)
{
	ThreadParam tp = thread->tp;
	return QString("%1:%2:%3:%4:%5: ").arg(
		QString::number(thread->handle, 16),
		QString::number(tp.pid, 16),
		QString::number(tp.hook, 16),
		QString::number(tp.retn, 16),
		QString::number(tp.spl, 16)
	).toUpper();
}

ThreadParam MainWindow::ParseTextThreadString(QString textThreadString)
{
	QStringList threadParam = textThreadString.split(":");
	return { threadParam[1].toUInt(nullptr, 16), threadParam[2].toULongLong(nullptr, 16), threadParam[3].toULongLong(nullptr, 16), threadParam[4].toULongLong(nullptr, 16) };
}

DWORD MainWindow::GetSelectedProcessId()
{
	return processCombo->currentText().split(":")[0].toULong(nullptr, 16);
}

void MainWindow::ReloadExtensions()
{
	extenCombo->clear();
	std::map<int, QString> extensions = LoadExtensions();
	for (auto i : extensions) extenCombo->addItem(QString::number(i.first) + ": " + i.second);
}

std::unordered_map<std::string, int64_t> MainWindow::GetInfoForExtensions(TextThread* thread)
{
	return 
	{
	{ "current select", ttCombo->currentText().startsWith(TextThreadString(thread)) },
	{ "text number", thread->handle },
	{ "process id", thread->tp.pid },
	{ "hook address", thread->tp.hook },
	{ "text handle", thread->handle },
	{ "text name", (int64_t)thread->name.c_str() }
	};
}

QVector<HookParam> MainWindow::GetAllHooks(DWORD processId)
{
	QSet<DWORD> addresses;
	QVector<HookParam> hooks;
	for (int i = 0; i < ttCombo->count(); ++i)
	{
		ThreadParam tp = ParseTextThreadString(ttCombo->itemText(i));
		if (tp.pid == processId && !addresses.contains(tp.hook))
		{
			addresses.insert(tp.hook);
			hooks.push_back(Host::GetHookParam(tp));
		}
	}
	return hooks;
}

void MainWindow::on_attachButton_clicked()
{
	QMultiHash<QString, DWORD> allProcesses = GetAllProcesses();
	QStringList processList(allProcesses.uniqueKeys());
	processList.sort(Qt::CaseInsensitive);
	bool ok;
	QString process = QInputDialog::getItem(this, "Select Process",
		"If you don't see the process you want to inject, try running with admin rights\r\nYou can also type in the process id if you know it",
		processList, 0, true, &ok);
	bool injected = false;
	if (!ok) return;
	if (process.toInt(nullptr, 0)) injected |= Host::InjectProcess(process.toInt(nullptr, 0));
	else for (auto i : allProcesses.values(process)) injected |= Host::InjectProcess(i);
	if (!injected) Host::AddConsoleOutput(L"failed to inject");
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
	if (auto hp = ParseCode(hookCode)) Host::InsertHook(GetSelectedProcessId(), hp.value());
	else Host::AddConsoleOutput(L"invalid code");
}

void MainWindow::on_unhookButton_clicked()
{
	QVector<HookParam> hooks = GetAllHooks(GetSelectedProcessId());
	if (hooks.size() == 0)
	{
		Host::AddConsoleOutput(L"no hooks detected");
		return;
	}
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
	textOutput->setPlainText(QString::fromStdWString(Host::GetThread(ParseTextThreadString(ttCombo->itemText(index)))->GetStorage()));
	textOutput->moveCursor(QTextCursor::End);
}

void MainWindow::on_addExtenButton_clicked()
{
	QString extenFileName = QFileDialog::getOpenFileName(this, "Select Extension dll", "C:\\", "Extensions (*.dll)");
	if (!extenFileName.size()) return;
	QString extenName = extenFileName.split("/")[extenFileName.split("/").count() - 1];
	QString copyTo = QString::number(extenCombo->itemText(extenCombo->count() - 1).split(":")[0].toInt() + 1) + "_" + extenName;
	QFile::copy(extenFileName, copyTo);
	ReloadExtensions();
}

void MainWindow::on_rmvExtenButton_clicked()
{
	if (extenCombo->currentText().size() == 0) return;
	QString extenFileName = extenCombo->currentText().split(":")[0] + "_" + extenCombo->currentText().split(": ")[1] + ".dll";
	FreeLibrary(GetModuleHandleW(extenFileName.toStdWString().c_str()));
	QFile::remove(extenFileName);
	ReloadExtensions();
}

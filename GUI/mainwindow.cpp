#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "defs.h"
#include "extenwindow.h"
#include "misc.h"
#include <QInputDialog>

MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow),
	extenWindow(new ExtenWindow)
{
	ui->setupUi(this);

	processCombo = findChild<QComboBox*>("processCombo");
	ttCombo = findChild<QComboBox*>("ttCombo");
	textOutput = findChild<QPlainTextEdit*>("textOutput");

	if (settings.contains("Window")) this->setGeometry(settings.value("Window").toRect());
	// TODO: add GUI for changing these
	if (settings.contains("Default_Codepage")) DEFAULT_CODEPAGE = settings.value("Default_Codepage").toInt();
	if (settings.contains("Flush_Delay")) TextThread::flushDelay = settings.value("Flush_Delay").toInt();
	if (settings.contains("Max_Buffer_Size")) TextThread::maxBufferSize = settings.value("Max_Buffer_Size").toInt();

	qRegisterMetaType<std::shared_ptr<TextThread>>();

	connect(this, &MainWindow::SigAddProcess, this, &MainWindow::AddProcess);
	connect(this, &MainWindow::SigRemoveProcess, this, &MainWindow::RemoveProcess);
	connect(this, &MainWindow::SigAddThread, this, &MainWindow::AddThread);
	connect(this, &MainWindow::SigRemoveThread, this, &MainWindow::RemoveThread);
	connect(this, &MainWindow::SigThreadOutput, this, &MainWindow::ThreadOutput);

	Host::Start(
		[&](DWORD processId) { emit SigAddProcess(processId); },
		[&](DWORD processId) { emit SigRemoveProcess(processId); },
		[&](std::shared_ptr<TextThread> thread) { emit SigAddThread(thread); },
		[&](std::shared_ptr<TextThread> thread) { emit SigRemoveThread(thread); },
		[&](TextThread* thread, std::wstring& output) { return ProcessThreadOutput(thread, output); }
	);
	Host::AddConsoleOutput(L"Textractor beta v3.4.0 by Artikash\r\nSource code and more information available under GPLv3 at https://github.com/Artikash/Textractor");
}

MainWindow::~MainWindow()
{
	settings.setValue("Window", this->geometry());
	settings.setValue("Default_Codepage", DEFAULT_CODEPAGE);
	settings.setValue("Flush_Delay", TextThread::flushDelay);
	settings.setValue("Max_Buffer_Size", TextThread::maxBufferSize);
	settings.sync();
	delete ui;

	Host::Close();
}

void MainWindow::closeEvent(QCloseEvent*)
{
	QCoreApplication::quit(); // Need to do this to kill any windows that might've been made by extensions
}

void MainWindow::AddProcess(unsigned processId)
{
	processCombo->addItem(QString::number(processId, 16).toUpper() + ": " + GetModuleName(processId));
	QFile file("SavedHooks.txt");
	file.open(QIODevice::ReadOnly);
	QString processName = GetFullModuleName(processId);
	QStringList allProcesses = QString(file.readAll()).split("\r", QString::SkipEmptyParts);
	for (auto hooks = allProcesses.rbegin(); hooks != allProcesses.rend(); ++hooks)
		if (hooks->contains(processName))
		{
			for (auto hook : hooks->split(" , "))
				if (auto hp = ParseCode(hook)) Host::InsertHook(processId, hp.value());
			return;
		}
}

void MainWindow::RemoveProcess(unsigned processId)
{
	processCombo->removeItem(processCombo->findText(QString::number(processId, 16).toUpper() + ":", Qt::MatchStartsWith));
}

void MainWindow::AddThread(std::shared_ptr<TextThread> thread)
{
	ttCombo->addItem(
		TextThreadString(thread.get()) +
		QString::fromStdWString(thread->name) +
		" (" +
		GenerateCode(thread->hp, thread->tp.pid) +
		")"
	);
}

void MainWindow::RemoveThread(std::shared_ptr<TextThread> thread)
{
	int threadIndex = ttCombo->findText(TextThreadString(thread.get()), Qt::MatchStartsWith);
	if (threadIndex == ttCombo->currentIndex())
	{
		ttCombo->setCurrentIndex(0);
		on_ttCombo_activated(0);
	}
	ttCombo->removeItem(threadIndex);
}

void MainWindow::ThreadOutput(QString threadString, QString output)
{
	if (ttCombo->currentText().startsWith(threadString))
	{
		textOutput->moveCursor(QTextCursor::End);
		textOutput->insertPlainText(output);
		textOutput->moveCursor(QTextCursor::End);
	}
}

bool MainWindow::ProcessThreadOutput(TextThread* thread, std::wstring& output)
{
	if (DispatchSentenceToExtensions(output, GetMiscInfo(thread)))
	{
		output += L"\r\n";
		emit SigThreadOutput(TextThreadString(thread), QString::fromStdWString(output));
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

std::unordered_map<std::string, int64_t> MainWindow::GetMiscInfo(TextThread* thread)
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
	QSet<uint64_t> addresses;
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
		"If you don't see the process you want to inject, try running with admin rights\r\nYou can also type in the process id",
		processList, 0, true, &ok);
	bool injected = false;
	if (!ok) return;
	if (process.toInt(nullptr, 0)) injected |= Host::InjectProcess(process.toInt(nullptr, 0));
	else for (auto processId : allProcesses.values(process)) injected |= Host::InjectProcess(processId);
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
	if (hooks.empty()) return Host::AddConsoleOutput(L"no hooks detected");
	QStringList hookList;
	for (auto hook : hooks) 
		hookList.push_back(
			QString::fromStdWString(Host::GetHookName(GetSelectedProcessId(), hook.insertion_address)) +
			": " +
			GenerateCode(hook, GetSelectedProcessId())
		);
	bool ok;
	QString hook = QInputDialog::getItem(this, "Unhook", "Which hook to remove?", hookList, 0, false, &ok);
	if (ok) Host::RemoveHook(GetSelectedProcessId(), hooks.at(hookList.indexOf(hook)).insertion_address);
}

void MainWindow::on_saveButton_clicked()
{
	QVector<HookParam> hooks = GetAllHooks(GetSelectedProcessId());
	QString hookList = GetFullModuleName(GetSelectedProcessId());
	for (auto hook : hooks)
		if (!(hook.type & HOOK_ENGINE))
			hookList += " , " + GenerateCode(hook, GetSelectedProcessId());
	QFile file("SavedHooks.txt");
	file.open(QIODevice::Append);
	file.write((hookList + "\r\n").toUtf8());
}

void MainWindow::on_extenButton_clicked()
{
	extenWindow->activateWindow();
	extenWindow->showNormal();
}

void MainWindow::on_ttCombo_activated(int index)
{
	textOutput->setPlainText(QString::fromStdWString(Host::GetThread(ParseTextThreadString(ttCombo->itemText(index)))->GetStorage()));
	textOutput->moveCursor(QTextCursor::End);
}

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "text.h"
#include "extenwindow.h"
#include "setdialog.h"
#include "misc.h"
#include <QInputDialog>

MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow),
	extenWindow(new ExtenWindow(this))
{
	ui->setupUi(this);

	processCombo = findChild<QComboBox*>("processCombo");
	ttCombo = findChild<QComboBox*>("ttCombo");
	textOutput = findChild<QPlainTextEdit*>("textOutput");

	if (settings.contains(WINDOW)) setGeometry(settings.value(WINDOW).toRect());
	if (settings.contains(FLUSH_DELAY)) TextThread::flushDelay = settings.value(FLUSH_DELAY).toInt();
	if (settings.contains(MAX_BUFFER_SIZE)) TextThread::maxBufferSize = settings.value(MAX_BUFFER_SIZE).toInt();
	if (settings.contains(DEFAULT_CODEPAGE)) TextThread::defaultCodepage = settings.value(DEFAULT_CODEPAGE).toInt();

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
	Host::AddConsoleOutput(ABOUT);
}

MainWindow::~MainWindow()
{
	settings.setValue(WINDOW, geometry());
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
	if (processId == 0) return;
	processCombo->addItem(QString::number(processId, 16).toUpper() + ": " + GetModuleName(processId));
	QFile file(HOOK_SAVE_FILE);
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
		GenerateCode(thread->hp, thread->tp.processId) +
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
		QString::number(tp.processId, 16),
		QString::number(tp.addr, 16),
		QString::number(tp.ctx, 16),
		QString::number(tp.ctx2, 16)
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
	{ "process id", thread->tp.processId },
	{ "hook address", thread->tp.addr },
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
		if (tp.processId == processId && !addresses.contains(tp.addr))
		{
			addresses.insert(tp.addr);
			hooks.push_back(Host::GetHookParam(tp));
		}
	}
	return hooks;
}

void MainWindow::on_attachButton_clicked()
{
	auto allProcesses = GetAllProcesses();
	QStringList processList(allProcesses.uniqueKeys());
	processList.sort(Qt::CaseInsensitive);
	bool ok;
	QString process = QInputDialog::getItem(this, SELECT_PROCESS, ATTACH_INFO, processList, 0, true, &ok, Qt::WindowCloseButtonHint);
	if (!ok) return;
	if (process.toInt(nullptr, 0)) Host::InjectProcess(process.toInt(nullptr, 0));
	else for (auto processId : allProcesses.values(process)) Host::InjectProcess(processId);
}

void MainWindow::on_detachButton_clicked()
{
	Host::DetachProcess(GetSelectedProcessId());
}

void MainWindow::on_hookButton_clicked()
{
	bool ok;
	QString hookCode = QInputDialog::getText(this, ADD_HOOK, CODE_INFODUMP, QLineEdit::Normal, "", &ok, Qt::WindowCloseButtonHint);
	if (!ok) return;
	if (auto hp = ParseCode(hookCode)) Host::InsertHook(GetSelectedProcessId(), hp.value());
	else Host::AddConsoleOutput(INVALID_CODE);
}

void MainWindow::on_unhookButton_clicked()
{
	auto hooks = GetAllHooks(GetSelectedProcessId());
	if (hooks.empty()) return Host::AddConsoleOutput(NO_HOOKS);
	QStringList hookList;
	for (auto hp : hooks) 
		hookList.push_back(
			QString::fromStdWString(Host::GetHookName(GetSelectedProcessId(), hp.insertion_address)) +
			": " +
			GenerateCode(hp, GetSelectedProcessId())
		);
	bool ok;
	QString hook = QInputDialog::getItem(this, UNHOOK, REMOVE_HOOK, hookList, 0, false, &ok, Qt::WindowCloseButtonHint);
	if (ok) Host::RemoveHook(GetSelectedProcessId(), hooks.at(hookList.indexOf(hook)).insertion_address);
}

void MainWindow::on_saveButton_clicked()
{
	auto hooks = GetAllHooks(GetSelectedProcessId());
	QString hookList = GetFullModuleName(GetSelectedProcessId());
	for (auto hp : hooks)
		if (!(hp.type & HOOK_ENGINE))
			hookList += " , " + GenerateCode(hp, GetSelectedProcessId());
	QFile file(HOOK_SAVE_FILE);
	file.open(QIODevice::Append);
	file.write((hookList + "\r\n").toUtf8());
}

void MainWindow::on_setButton_clicked()
{
	SetDialog(this).exec();
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

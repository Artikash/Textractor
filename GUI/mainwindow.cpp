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
	Host::AddConsoleOutput(L"NextHooker beta v3.0.0 by Artikash\r\nSource code and more information available under GPLv3 at https://github.com/Artikash/NextHooker");
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
	processCombo->addItem(QString::number(processId) + ": " + GetModuleName(processId));
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

void MainWindow::RemoveProcess(unsigned int processId)
{
	processCombo->removeItem(processCombo->findText(QString::number(processId) + ":", Qt::MatchStartsWith));
}

void MainWindow::AddThread(TextThread* thread)
{
	ttCombo->addItem(
		TextThreadString(thread) +
		QString::fromStdWString(Host::GetHookName(thread->GetThreadParam().pid, thread->GetThreadParam().hook)) +
		" (" +
		GenerateCode(Host::GetHookParam(thread->GetThreadParam()), thread->GetThreadParam().pid) +
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

QString MainWindow::TextThreadString(TextThread* thread)
{
	ThreadParam tp = thread->GetThreadParam();
	return QString("%1:%2:%3:%4: ").arg(
		QString::number(tp.pid),
		QString::number(tp.hook, 16),
		QString::number(tp.retn, 16),
		QString::number(tp.spl, 16)
	).toUpper();
}

ThreadParam MainWindow::ParseTextThreadString(QString textThreadString)
{
	QStringList threadParam = textThreadString.split(":");
	return { threadParam[0].toUInt(), threadParam[1].toULongLong(nullptr, 16), threadParam[2].toULongLong(nullptr, 16), threadParam[3].toULongLong(nullptr, 16) };
}

DWORD MainWindow::GetSelectedProcessId()
{
	return processCombo->currentText().split(":")[0].toULong();
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
	{ "process id", thread->GetThreadParam().pid },
	{ "hook address", (int)thread->GetThreadParam().hook },
	{ "hook address (upper 32 bits)", (int)(thread->GetThreadParam().hook >> 32) }
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
	Host::AddConsoleOutput(L"failed to attach");
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
	textOutput->setPlainText(QString::fromStdWString(Host::GetThread(ParseTextThreadString(ttCombo->itemText(index)))->GetStore()));
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

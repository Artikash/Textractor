#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "text.h"
#include "extenwindow.h"
#include "setdialog.h"
#include "misc.h"
#include "host/util.h"
#include <QTimer>
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

	Host::Start(
		[&](DWORD processId) { ProcessConnected(processId); },
		[&](DWORD processId) { ProcessDisconnected(processId); },
		[&](TextThread* thread) { ThreadAdded(thread); },
		[&](TextThread* thread) { ThreadRemoved(thread); },
		[&](TextThread* thread, std::wstring& output) { return SentenceReceived(thread, output); }
	);
	Host::AddConsoleOutput(ABOUT);
}

MainWindow::~MainWindow()
{
	Host::Shutdown();
	settings.setValue(WINDOW, geometry());
	settings.sync();
	delete ui;
}

void MainWindow::closeEvent(QCloseEvent*)
{
	QCoreApplication::quit(); // Need to do this to kill any windows that might've been made by extensions
}


void MainWindow::InvokeOnMainThread(std::function<void()> f)
{
	QMetaObject::invokeMethod(this, f);
}

void MainWindow::ProcessConnected(DWORD processId)
{
	if (processId == 0) return;
	InvokeOnMainThread([&, processId]
	{
		QString process = QString::fromStdWString(Util::GetModuleFileName(processId).value());
		processCombo->addItem(QString::number(processId, 16).toUpper() + ": " + QFileInfo(process).fileName());

		QStringList allProcesses = QString(QAutoFile(HOOK_SAVE_FILE, QIODevice::ReadOnly)->readAll()).split("\r", QString::SkipEmptyParts);
		// Can't use QFileInfo::absoluteFilePath since hook save file has '\\' as path separator
		auto hookList = std::find_if(allProcesses.rbegin(), allProcesses.rend(), [&](QString hookList) { return hookList.contains(process); });
		if (hookList != allProcesses.rend())
			for (auto hookCode : hookList->split(" , "))
				if (auto hp = ParseCode(hookCode)) Host::InsertHook(processId, hp.value());
	});
}

void MainWindow::ProcessDisconnected(DWORD processId)
{
	InvokeOnMainThread([&, processId] { processCombo->removeItem(processCombo->findText(QString::number(processId, 16).toUpper() + ":", Qt::MatchStartsWith)); });
}

void MainWindow::ThreadAdded(TextThread* thread)
{
	QString ttString = TextThreadString(thread) + QString::fromStdWString(thread->name) + " (" + GenerateCode(thread->hp, thread->tp.processId) + ")";
	InvokeOnMainThread([&, ttString] { ttCombo->addItem(ttString); });
}

void MainWindow::ThreadRemoved(TextThread* thread)
{
	QString ttString = TextThreadString(thread);
	InvokeOnMainThread([&, ttString]
	{
		int threadIndex = ttCombo->findText(ttString, Qt::MatchStartsWith);
		if (threadIndex == ttCombo->currentIndex())
		{
			ttCombo->setCurrentIndex(0);
			on_ttCombo_activated(0);
		}
		ttCombo->removeItem(threadIndex);
	});
}

bool MainWindow::SentenceReceived(TextThread* thread, std::wstring& sentence)
{
	if (DispatchSentenceToExtensions(sentence, GetMiscInfo(thread)))
	{
		sentence += L"\r\n";
		QString ttString = TextThreadString(thread);
		InvokeOnMainThread([&, ttString, sentence]
		{
			if (ttCombo->currentText().startsWith(ttString))
			{
				textOutput->moveCursor(QTextCursor::End);
				textOutput->insertPlainText(QString::fromStdWString(sentence));
				textOutput->moveCursor(QTextCursor::End);
			}
		});
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

ThreadParam MainWindow::ParseTextThreadString(QString ttString)
{
	QStringList threadParam = ttString.split(":");
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

void MainWindow::on_saveButton_clicked()
{
	QHash<uint64_t, QString> hookCodes;
	for (int i = 0; i < ttCombo->count(); ++i)
	{
		ThreadParam tp = ParseTextThreadString(ttCombo->itemText(i));
		if (tp.processId == GetSelectedProcessId() && !(Host::GetHookParam(tp).type & HOOK_ENGINE)) hookCodes[tp.addr] = GenerateCode(Host::GetHookParam(tp), tp.processId);
	}
	QString hookList = QString::fromStdWString(Util::GetModuleFileName(GetSelectedProcessId()).value());
	for (auto hookCode : hookCodes) hookList += " , " + hookCode;
	QAutoFile(HOOK_SAVE_FILE, QIODevice::Append)->write((hookList + "\r\n").toUtf8());
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

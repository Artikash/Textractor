#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "defs.h"
#include "text.h"
#include "extenwindow.h"
#include "misc.h"
#include "host/util.h"
#include <Psapi.h>
#include <winhttp.h>
#include <QFormLayout>
#include <QPushButton>
#include <QSpinBox>
#include <QInputDialog>

MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow),
	extenWindow(new ExtenWindow(this))
{
	ui->setupUi(this);
	for (auto[text, slot] : Array<std::tuple<QString, void(MainWindow::*)()>>{
		{ ATTACH, &MainWindow::AttachProcess },
		{ DETACH, &MainWindow::DetachProcess },
		{ ADD_HOOK, &MainWindow::AddHook },
		{ SAVE_HOOKS, &MainWindow::SaveHooks },
		{ SETTINGS, &MainWindow::Settings },
		{ EXTENSIONS, &MainWindow::Extensions }
	})
	{
		QPushButton* button = new QPushButton(ui->processFrame);
		connect(button, &QPushButton::clicked, this, slot);
		button->setText(text);
		ui->processLayout->addWidget(button);
	}
	ui->processLayout->addItem(new QSpacerItem(0, 0, QSizePolicy::Minimum, QSizePolicy::Expanding));

	connect(ui->ttCombo, (void(QComboBox::*)(int))&QComboBox::activated, this, &MainWindow::ViewThread);

	QSettings settings(CONFIG_FILE, QSettings::IniFormat);
	if (settings.contains(WINDOW)) setGeometry(settings.value(WINDOW).toRect());
	if (settings.contains(FLUSH_DELAY)) TextThread::flushDelay = settings.value(FLUSH_DELAY).toInt();
	if (settings.contains(MAX_BUFFER_SIZE)) TextThread::maxBufferSize = settings.value(MAX_BUFFER_SIZE).toInt();
	if (settings.contains(DEFAULT_CODEPAGE)) TextThread::defaultCodepage = settings.value(DEFAULT_CODEPAGE).toInt();
	settings.sync();

	Host::Start(
		[this](DWORD processId) { ProcessConnected(processId); },
		[this](DWORD processId) { ProcessDisconnected(processId); },
		[this](TextThread* thread) { ThreadAdded(thread); },
		[this](TextThread* thread) { ThreadRemoved(thread); },
		[this](TextThread* thread, std::wstring& output) { return SentenceReceived(thread, output); }
	);
	Host::AddConsoleOutput(ABOUT);

	std::thread([]
	{
		// Queries GitHub releases API https://developer.github.com/v3/repos/releases/ and checks the last release tag to check if it's the same
		struct InternetHandleCloser { void operator()(void* h) { WinHttpCloseHandle(h); } };
		if (AutoHandle<InternetHandleCloser> internet = WinHttpOpen(L"Mozilla/5.0 Textractor", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0))
			if (AutoHandle<InternetHandleCloser> connection = WinHttpConnect(internet, L"api.github.com", INTERNET_DEFAULT_HTTPS_PORT, 0))
				if (AutoHandle<InternetHandleCloser> request = WinHttpOpenRequest(connection, L"GET", L"/repos/Artikash/Textractor/releases", NULL, NULL, NULL, WINHTTP_FLAG_SECURE))
					if (WinHttpSendRequest(request, NULL, 0, NULL, 0, 0, NULL))
					{
						DWORD bytesRead;
						char buffer[1000] = {};
						WinHttpReceiveResponse(request, NULL);
						WinHttpReadData(request, buffer, 1000, &bytesRead);
						if (abs(strstr(buffer, "/tag/") - strstr(buffer, CURRENT_VERSION)) > 10) Host::AddConsoleOutput(UPDATE_AVAILABLE);
					}
	}).detach();
}

MainWindow::~MainWindow()
{
	QSettings settings(CONFIG_FILE, QSettings::IniFormat);
	settings.setValue(WINDOW, geometry());
	settings.sync();
	ExitProcess(0);
}

void MainWindow::closeEvent(QCloseEvent*)
{
	QCoreApplication::quit(); // Need to do this to kill any windows that might've been made by extensions
}

void MainWindow::ProcessConnected(DWORD processId)
{
	if (processId == 0) return;
	QMetaObject::invokeMethod(this, [this, processId]
	{
		QString process = S(Util::GetModuleFilename(processId).value());
		ui->processCombo->addItem(QString::number(processId, 16).toUpper() + ": " + QFileInfo(process).fileName());

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
	QMetaObject::invokeMethod(this, [this, processId] { ui->processCombo->removeItem(ui->processCombo->findText(QString::number(processId, 16).toUpper() + ":", Qt::MatchStartsWith)); });
}

void MainWindow::ThreadAdded(TextThread* thread)
{
	QString ttString = TextThreadString(thread) + S(thread->name) + " (" + GenerateCode(thread->hp, thread->tp.processId) + ")";
	QMetaObject::invokeMethod(this, [this, ttString] { ui->ttCombo->addItem(ttString); });
}

void MainWindow::ThreadRemoved(TextThread* thread)
{
	QString ttString = TextThreadString(thread);
	QMetaObject::invokeMethod(this, [this, ttString]
	{
		int threadIndex = ui->ttCombo->findText(ttString, Qt::MatchStartsWith);
		if (threadIndex == ui->ttCombo->currentIndex())
		{
			ui->ttCombo->setCurrentIndex(0);
			ViewThread(0);
		}
		ui->ttCombo->removeItem(threadIndex);
	});
}

bool MainWindow::SentenceReceived(TextThread* thread, std::wstring& sentence)
{
	if (DispatchSentenceToExtensions(sentence, GetMiscInfo(thread)))
	{
		sentence += L"\r\n";
		QString ttString = TextThreadString(thread);
		QMetaObject::invokeMethod(this, [this, ttString, sentence]
		{
			if (ui->ttCombo->currentText().startsWith(ttString))
			{
				ui->textOutput->moveCursor(QTextCursor::End);
				ui->textOutput->insertPlainText(S(sentence));
				ui->textOutput->moveCursor(QTextCursor::End);
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
	return ui->processCombo->currentText().split(":")[0].toULong(nullptr, 16);
}

std::unordered_map<std::string, int64_t> MainWindow::GetMiscInfo(TextThread* thread)
{
	return 
	{
	{ "current select", ui->ttCombo->currentText().startsWith(TextThreadString(thread)) },
	{ "text number", thread->handle },
	{ "process id", thread->tp.processId },
	{ "hook address", thread->tp.addr },
	{ "text handle", thread->handle },
	{ "text name", (int64_t)thread->name.c_str() }
	};
}

void MainWindow::AttachProcess()
{
	QMultiHash<QString, DWORD> allProcesses;
	DWORD allProcessIds[5000] = {}, spaceUsed = 0;
	EnumProcesses(allProcessIds, sizeof(allProcessIds), &spaceUsed);
	for (int i = 0; i < spaceUsed / sizeof(DWORD); ++i)
		if (auto processName = Util::GetModuleFilename(allProcessIds[i])) allProcesses.insert(QFileInfo(S(processName.value())).fileName(), allProcessIds[i]);

	QStringList processList(allProcesses.uniqueKeys());
	processList.sort(Qt::CaseInsensitive);
	bool ok;
	QString process = QInputDialog::getItem(this, SELECT_PROCESS, ATTACH_INFO, processList, 0, true, &ok, Qt::WindowCloseButtonHint);
	if (!ok) return;
	if (process.toInt(nullptr, 0)) Host::InjectProcess(process.toInt(nullptr, 0));
	else for (auto processId : allProcesses.values(process)) Host::InjectProcess(processId);
}

void MainWindow::DetachProcess()
{
	Host::DetachProcess(GetSelectedProcessId());
}

void MainWindow::AddHook()
{
	bool ok;
	QString hookCode = QInputDialog::getText(this, ADD_HOOK, CODE_INFODUMP, QLineEdit::Normal, "", &ok, Qt::WindowCloseButtonHint);
	if (!ok) return;
	if (auto hp = ParseCode(hookCode)) Host::InsertHook(GetSelectedProcessId(), hp.value());
	else Host::AddConsoleOutput(INVALID_CODE);
}

void MainWindow::SaveHooks()
{
	if (auto processName = Util::GetModuleFilename(GetSelectedProcessId()))
	{
		QHash<uint64_t, QString> hookCodes;
		for (int i = 0; i < ui->ttCombo->count(); ++i)
		{
			ThreadParam tp = ParseTextThreadString(ui->ttCombo->itemText(i));
			if (tp.processId == GetSelectedProcessId() && !(Host::GetHookParam(tp).type & HOOK_ENGINE)) hookCodes[tp.addr] = GenerateCode(Host::GetHookParam(tp), tp.processId);
		}
		QString hookList = S(processName.value());
		for (auto hookCode : hookCodes) hookList += " , " + hookCode;
		QAutoFile(HOOK_SAVE_FILE, QIODevice::Append)->write((hookList + "\r\n").toUtf8());
	}
}

void MainWindow::Settings()
{
	struct : QDialog
	{
		using QDialog::QDialog;
		void launch()
		{
			auto settings = new QSettings(CONFIG_FILE, QSettings::IniFormat, this);
			auto layout = new QFormLayout(this);
			auto save = new QPushButton(this);
			save->setText(SAVE_SETTINGS);
			layout->addWidget(save);
			for (auto[value, label] : Array<std::tuple<int&, const char*>>{
				{ TextThread::defaultCodepage, DEFAULT_CODEPAGE },
				{ TextThread::maxBufferSize, MAX_BUFFER_SIZE },
				{ TextThread::flushDelay, FLUSH_DELAY },
			})
			{
				auto spinBox = new QSpinBox(this);
				spinBox->setMaximum(INT_MAX);
				spinBox->setValue(value);
				layout->insertRow(0, label, spinBox);
				connect(save, &QPushButton::clicked, [=, &value] { settings->setValue(label, value = spinBox->value()); settings->sync(); });
			}
			connect(save, &QPushButton::clicked, this, &QDialog::accept);
			setWindowTitle(SETTINGS);
			exec();
		}
	} settingsDialog(this, Qt::WindowCloseButtonHint);
	settingsDialog.launch();
}

void MainWindow::Extensions()
{
	extenWindow->activateWindow();
	extenWindow->showNormal();
}

void MainWindow::ViewThread(int index)
{
	ui->textOutput->setPlainText(S(Host::GetThread(ParseTextThreadString(ui->ttCombo->itemText(index)))->storage->c_str()));
	ui->textOutput->moveCursor(QTextCursor::End);
}

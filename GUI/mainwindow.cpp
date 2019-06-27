#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "defs.h"
#include "host/util.h"
#include <shellapi.h>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QSpinBox>
#include <QListWidget>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>

extern const char* ATTACH;
extern const char* LAUNCH;
extern const char* DETACH;
extern const char* FORGET;
extern const char* ADD_HOOK;
extern const char* REMOVE_HOOKS;
extern const char* SAVE_HOOKS;
extern const char* SEARCH_FOR_HOOKS;
extern const char* SETTINGS;
extern const char* EXTENSIONS;
extern const char* SELECT_PROCESS;
extern const char* ATTACH_INFO;
extern const char* SEARCH_GAME;
extern const char* PROCESSES;
extern const char* CODE_INFODUMP;
extern const char* HOOK_SEARCH_UNSTABLE_WARNING;
extern const char* SEARCH_CJK;
extern const char* SEARCH_PATTERN;
extern const char* SEARCH_DURATION;
extern const char* PATTERN_OFFSET;
extern const char* MIN_ADDRESS;
extern const char* MAX_ADDRESS;
extern const char* STRING_OFFSET;
extern const char* HOOK_SEARCH_FILTER;
extern const char* START_HOOK_SEARCH;
extern const char* SAVE_SEARCH_RESULTS;
extern const char* TEXT_FILES;
extern const char* DOUBLE_CLICK_TO_REMOVE_HOOK;
extern const char* SAVE_SETTINGS;
extern const char* USE_JP_LOCALE;
extern const char* FILTER_REPETITION;
extern const char* AUTO_ATTACH;
extern const char* ATTACH_SAVED_ONLY;
extern const char* DEFAULT_CODEPAGE;
extern const char* FLUSH_DELAY;
extern const char* MAX_BUFFER_SIZE;
extern const wchar_t* ABOUT;
extern const wchar_t* CL_OPTIONS;
extern const wchar_t* LAUNCH_FAILED;
extern const wchar_t* INVALID_CODE;

MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow),
	extenWindow(new ExtenWindow(this))
{
	ui->setupUi(this);
	for (auto [text, slot] : Array<std::tuple<QString, void(MainWindow::*)()>>{
		{ ATTACH, &MainWindow::AttachProcess },
		{ LAUNCH, &MainWindow::LaunchProcess },
		{ DETACH, &MainWindow::DetachProcess },
		{ FORGET, &MainWindow::ForgetProcess },
		{ ADD_HOOK, &MainWindow::AddHook },
		{ REMOVE_HOOKS, &MainWindow::RemoveHooks },
		{ SAVE_HOOKS, &MainWindow::SaveHooks },
		{ SEARCH_FOR_HOOKS, &MainWindow::FindHooks },
		{ SETTINGS, &MainWindow::Settings },
		{ EXTENSIONS, &MainWindow::Extensions }
	})
	{
		auto button = new QPushButton(ui->processFrame);
		connect(button, &QPushButton::clicked, this, slot);
		button->setText(text);
		ui->processLayout->addWidget(button);
	}
	ui->processLayout->addItem(new QSpacerItem(0, 0, QSizePolicy::Minimum, QSizePolicy::Expanding));

	connect(ui->ttCombo, qOverload<int>(&QComboBox::activated), this, &MainWindow::ViewThread);
	connect(ui->textOutput, &QPlainTextEdit::selectionChanged, [this] { if (!(QApplication::mouseButtons() & Qt::LeftButton)) ui->textOutput->copy(); });

	QSettings settings(CONFIG_FILE, QSettings::IniFormat);
	if (settings.contains(WINDOW)) setGeometry(settings.value(WINDOW).toRect());
	TextThread::filterRepetition = settings.value(FILTER_REPETITION, TextThread::filterRepetition).toBool();
	autoAttach = settings.value(AUTO_ATTACH, autoAttach).toBool();
	autoAttachSavedOnly = settings.value(ATTACH_SAVED_ONLY, autoAttachSavedOnly).toBool();
	TextThread::flushDelay = settings.value(FLUSH_DELAY, TextThread::flushDelay).toInt();
	TextThread::maxBufferSize = settings.value(MAX_BUFFER_SIZE, TextThread::maxBufferSize).toInt();
	Host::defaultCodepage = settings.value(DEFAULT_CODEPAGE, Host::defaultCodepage).toInt();

	Host::Start(
		[this](DWORD processId) { ProcessConnected(processId); },
		[this](DWORD processId) { ProcessDisconnected(processId); },
		[this](TextThread& thread) { ThreadAdded(thread); },
		[this](TextThread& thread) { ThreadRemoved(thread); },
		[this](TextThread& thread, std::wstring& output) { return SentenceReceived(thread, output); }
	);
	current = &Host::GetThread(Host::console);
	Host::AddConsoleOutput(ABOUT);

	AttachConsole(ATTACH_PARENT_PROCESS);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), CL_OPTIONS, wcslen(CL_OPTIONS), DUMMY, NULL);
	auto processes = Util::GetAllProcesses();
	int argc;
	std::unique_ptr<LPWSTR[], Functor<LocalFree>> argv(CommandLineToArgvW(GetCommandLineW(), &argc));
	for (int i = 0; i < argc; ++i)
		if (std::wstring arg = argv[i]; arg[0] == L'/' || arg[0] == L'-')
			if (arg[1] == L'p' || arg[1] == L'P')
				if (DWORD processId = _wtoi(arg.substr(2).c_str())) Host::InjectProcess(processId);
				else for (auto [processId, processName] : processes)
					if (processName.value_or(L"").find(L"\\" + arg.substr(2)) != std::wstring::npos) Host::InjectProcess(processId);

	std::thread([this]
	{
		for (; ; Sleep(10000))
		{
			std::unordered_set<std::wstring> attachTargets;
			if (autoAttach)
				for (auto process : QString(QTextFile(GAME_SAVE_FILE, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts))
					attachTargets.insert(S(process));
			if (autoAttachSavedOnly)
				for (auto process : QString(QTextFile(HOOK_SAVE_FILE, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts))
					attachTargets.insert(S(process.split(" , ")[0]));

			if (!attachTargets.empty())
				for (auto [processId, processName] : Util::GetAllProcesses())
					if (processName && attachTargets.count(processName.value()) > 0 && alreadyAttached.count(processId) == 0) Host::InjectProcess(processId);
		}
	}).detach();
}

MainWindow::~MainWindow()
{
	QSettings(CONFIG_FILE, QSettings::IniFormat).setValue(WINDOW, geometry());
	CleanupExtensions();
	SetErrorMode(SEM_NOGPFAULTERRORBOX);
	ExitProcess(0);
}

void MainWindow::closeEvent(QCloseEvent*)
{
	QCoreApplication::quit(); // Need to do this to kill any windows that might've been made by extensions
}

void MainWindow::ProcessConnected(DWORD processId)
{
	alreadyAttached.insert(processId);

	QString process = S(Util::GetModuleFilename(processId).value_or(L"???"));
	QMetaObject::invokeMethod(this, [this, process, processId]
	{
		ui->processCombo->addItem(QString::number(processId, 16).toUpper() + ": " + QFileInfo(process).fileName());
	});
	if (process == "???") return;

	// This does add (potentially tons of) duplicates to the file, but as long as I don't perform Ω(N^2) operations it shouldn't be an issue
	QTextFile(GAME_SAVE_FILE, QIODevice::WriteOnly | QIODevice::Append).write((process + "\n").toUtf8());

	QStringList allProcesses = QString(QTextFile(HOOK_SAVE_FILE, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts);
	// Can't use QFileInfo::absoluteFilePath since hook save file has '\\' as path separator
	auto hookList = std::find_if(allProcesses.rbegin(), allProcesses.rend(), [&](QString hookList) { return hookList.contains(process); });
	if (hookList != allProcesses.rend())
		for (auto hookInfo : hookList->split(" , "))
			if (auto hp = Util::ParseCode(S(hookInfo))) Host::InsertHook(processId, hp.value());
			else swscanf_s(S(hookInfo).c_str(), L"|%I64d:%I64d:%[^\n]", &savedThreadCtx, &savedThreadCtx2, savedThreadCode, (unsigned)std::size(savedThreadCode));
}

void MainWindow::ProcessDisconnected(DWORD processId)
{
	QMetaObject::invokeMethod(this, [this, processId]
	{
		ui->processCombo->removeItem(ui->processCombo->findText(QString::number(processId, 16).toUpper() + ":", Qt::MatchStartsWith));
	}, Qt::BlockingQueuedConnection);
}

void MainWindow::ThreadAdded(TextThread& thread)
{
	std::wstring threadCode = Util::GenerateCode(thread.hp, thread.tp.processId);
	QString ttString = TextThreadString(thread) + S(thread.name) + " (" + S(threadCode) + ")";
	bool savedMatch = savedThreadCtx == thread.tp.ctx && savedThreadCtx2 == thread.tp.ctx2 && savedThreadCode == threadCode;
	if (savedMatch) savedThreadCtx = savedThreadCtx2 = savedThreadCode[0] = 0;
	QMetaObject::invokeMethod(this, [this, ttString, savedMatch]
	{
		ui->ttCombo->addItem(ttString);
		if (savedMatch) ViewThread(ui->ttCombo->count() - 1);
	});
}

void MainWindow::ThreadRemoved(TextThread& thread)
{
	QString ttString = TextThreadString(thread);
	QMetaObject::invokeMethod(this, [this, ttString]
	{
		int threadIndex = ui->ttCombo->findText(ttString, Qt::MatchStartsWith);
		if (threadIndex == ui->ttCombo->currentIndex())	ViewThread(0);
		ui->ttCombo->removeItem(threadIndex);
	}, Qt::BlockingQueuedConnection);
}

bool MainWindow::SentenceReceived(TextThread& thread, std::wstring& sentence)
{
	if (!DispatchSentenceToExtensions(sentence, GetMiscInfo(thread).data())) return false;
	sentence += L'\n';
	if (current == &thread) QMetaObject::invokeMethod(this, [this, sentence]
	{
		ui->textOutput->moveCursor(QTextCursor::End);
		ui->textOutput->insertPlainText(S(sentence));
		ui->textOutput->moveCursor(QTextCursor::End);
	});
	return true;
}

QString MainWindow::TextThreadString(TextThread& thread)
{
	return QString("%1:%2:%3:%4:%5: ").arg(
		QString::number(thread.handle, 16),
		QString::number(thread.tp.processId, 16),
		QString::number(thread.tp.addr, 16),
		QString::number(thread.tp.ctx, 16),
		QString::number(thread.tp.ctx2, 16)
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

std::array<InfoForExtension, 10> MainWindow::GetMiscInfo(TextThread& thread)
{
	void(*AddSentence)(MainWindow*, int64_t, const wchar_t*) = [](MainWindow* This, int64_t number, const wchar_t* sentence)
	{
		std::wstring copy = sentence;
		// pointer from Host::GetThread may not stay valid unless on main thread
		QMetaObject::invokeMethod(This, [=]() mutable { if (TextThread* thread = Host::GetThread(number)) thread->AddSentence(std::move(copy)); });
	};

	return
	{ {
	{ "current select", &thread == current },
	{ "text number", thread.handle },
	{ "process id", thread.tp.processId },
	{ "hook address", (int64_t)thread.tp.addr },
	{ "text handle", thread.handle },
	{ "text name", (int64_t)thread.name.c_str() },
	{ "this", (int64_t)this },
	{ "void (*AddSentence)(void* this, int64_t number, const wchar_t* sentence)", (int64_t)AddSentence },
	{ nullptr, 0 } // nullptr marks end of info array
	} };
}

void MainWindow::AttachProcess()
{
	QMultiHash<QString, DWORD> allProcesses;
	for (auto [processId, processName] : Util::GetAllProcesses())
		if (processName) allProcesses.insert(QFileInfo(S(processName.value())).fileName(), processId);

	QStringList processList(allProcesses.uniqueKeys());
	processList.sort(Qt::CaseInsensitive);
	if (QString process = QInputDialog::getItem(this, SELECT_PROCESS, ATTACH_INFO, processList, 0, true, &ok, Qt::WindowCloseButtonHint); ok)
		if (process.toInt(nullptr, 0)) Host::InjectProcess(process.toInt(nullptr, 0));
		else for (auto processId : allProcesses.values(process)) Host::InjectProcess(processId);
}

void MainWindow::LaunchProcess()
{
	QStringList savedProcesses = QString::fromUtf8(QTextFile(GAME_SAVE_FILE, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts);
	std::reverse(savedProcesses.begin(), savedProcesses.end());
	savedProcesses.removeDuplicates();
	savedProcesses.push_back(SEARCH_GAME);
	std::wstring process = S(QInputDialog::getItem(this, SELECT_PROCESS, "", savedProcesses, 0, true, &ok, Qt::WindowCloseButtonHint));
	if (!ok) return;
	if (S(process) == SEARCH_GAME) process = S(QDir::toNativeSeparators(QFileDialog::getOpenFileName(this, SELECT_PROCESS, "C:\\", PROCESSES)));
	if (process.find(L'\\') == std::wstring::npos) return;
	std::wstring path = std::wstring(process).erase(process.rfind(L'\\'));

	PROCESS_INFORMATION info = {};
	if (!x64 && QMessageBox::question(this, SELECT_PROCESS, USE_JP_LOCALE) == QMessageBox::Yes)
	{
		if (HMODULE localeEmulator = LoadLibraryOnce(L"LoaderDll"))
		{
			// see https://github.com/xupefei/Locale-Emulator/blob/aa99dec3b25708e676c90acf5fed9beaac319160/LEProc/LoaderWrapper.cs#L252
			struct
			{
				ULONG AnsiCodePage = SHIFT_JIS;
				ULONG OemCodePage = SHIFT_JIS;
				ULONG LocaleID = LANG_JAPANESE;
				ULONG DefaultCharset = SHIFTJIS_CHARSET;
				ULONG HookUiLanguageApi = FALSE;
				WCHAR DefaultFaceName[LF_FACESIZE] = {};
				TIME_ZONE_INFORMATION Timezone;
				ULONG64 Unused = 0;
			} LEB;
			GetTimeZoneInformation(&LEB.Timezone);
			((LONG(__stdcall*)(decltype(&LEB), LPCWSTR appName, LPWSTR commandLine, LPCWSTR currentDir, void*, void*, PROCESS_INFORMATION*, void*, void*, void*, void*))
				GetProcAddress(localeEmulator, "LeCreateProcess"))(&LEB, process.c_str(), NULL, path.c_str(), NULL, NULL, &info, NULL, NULL, NULL, NULL);
		}
	}
	if (info.hProcess == NULL)
	{
		STARTUPINFOW DUMMY = { sizeof(DUMMY) };
		CreateProcessW(process.c_str(), NULL, nullptr, nullptr, FALSE, 0, nullptr, path.c_str(), &DUMMY, &info);
	}
	if (info.hProcess == NULL) return Host::AddConsoleOutput(LAUNCH_FAILED);
	Host::InjectProcess(info.dwProcessId);
	CloseHandle(info.hProcess);
	CloseHandle(info.hThread);
}

void MainWindow::DetachProcess()
{
	try { Host::DetachProcess(GetSelectedProcessId()); } catch (std::out_of_range) {}
}

void MainWindow::ForgetProcess()
{
	if (auto processName = Util::GetModuleFilename(GetSelectedProcessId()))
	{
		for (auto file : { GAME_SAVE_FILE, HOOK_SAVE_FILE })
		{
			QStringList lines = QString::fromUtf8(QTextFile(file, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts);
			lines.erase(std::remove_if(lines.begin(), lines.end(), [&](auto line) { return line.contains(S(processName.value())); }), lines.end());
			QTextFile(file, QIODevice::WriteOnly | QIODevice::Truncate).write(lines.join("\n").toUtf8());
		}
	}
	DetachProcess();
}

void MainWindow::AddHook()
{
	if (QString hookCode = QInputDialog::getText(this, ADD_HOOK, CODE_INFODUMP, QLineEdit::Normal, "", &ok, Qt::WindowCloseButtonHint); ok)
		if (auto hp = Util::ParseCode(S(hookCode))) try { Host::InsertHook(GetSelectedProcessId(), hp.value()); } catch (std::out_of_range) {}
		else Host::AddConsoleOutput(INVALID_CODE);
}

void MainWindow::RemoveHooks()
{
	DWORD processId = GetSelectedProcessId();
	std::unordered_map<uint64_t, HookParam> hooks;
	for (int i = 0; i < ui->ttCombo->count(); ++i)
	{
		ThreadParam tp = ParseTextThreadString(ui->ttCombo->itemText(i));
		if (tp.processId == GetSelectedProcessId()) hooks[tp.addr] = Host::GetThread(tp).hp;
	}
	auto hookList = new QListWidget(this);
	hookList->setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint);
	hookList->setAttribute(Qt::WA_DeleteOnClose);
	hookList->setMinimumSize({ 300, 50 });
	hookList->setWindowTitle(DOUBLE_CLICK_TO_REMOVE_HOOK);
	for (auto [address, hp] : hooks)
		new QListWidgetItem(QString(hp.name) + "@" + QString::number(address, 16), hookList);
	connect(hookList, &QListWidget::itemDoubleClicked, [processId, hookList](QListWidgetItem* item)
	{
		try
		{
			Host::RemoveHook(processId, item->text().split("@")[1].toULongLong(nullptr, 16));
			delete item;
		}
		catch (std::out_of_range) { hookList->close(); }
	});
	hookList->show();
}

void MainWindow::SaveHooks()
{
	auto processName = Util::GetModuleFilename(GetSelectedProcessId());
	if (!processName) return;
	QHash<uint64_t, QString> hookCodes;
	for (int i = 0; i < ui->ttCombo->count(); ++i)
	{
		ThreadParam tp = ParseTextThreadString(ui->ttCombo->itemText(i));
		if (tp.processId == GetSelectedProcessId())
		{
			HookParam hp = Host::GetThread(tp).hp;
			if (!(hp.type & HOOK_ENGINE)) hookCodes[tp.addr] = S(Util::GenerateCode(hp, tp.processId));
		}
	}
	auto hookInfo = QStringList() << S(processName.value()) << hookCodes.values();
	ThreadParam tp = current->tp;
	if (tp.processId == GetSelectedProcessId()) hookInfo << QString("|%1:%2:%3").arg(tp.ctx).arg(tp.ctx2).arg(S(Util::GenerateCode(current->hp, tp.processId)));
	QTextFile(HOOK_SAVE_FILE, QIODevice::WriteOnly | QIODevice::Append).write((hookInfo.join(" , ") + "\n").toUtf8());
}

void MainWindow::FindHooks()
{
	QMessageBox::information(this, SEARCH_FOR_HOOKS, HOOK_SEARCH_UNSTABLE_WARNING);

	DWORD processId = GetSelectedProcessId();
	SearchParam sp = {};
	bool customSettings = false;
	std::wregex filter(L".");
	
	QDialog dialog(this, Qt::WindowCloseButtonHint);
	QFormLayout layout(&dialog);
	QCheckBox cjkCheckbox(&dialog);
	layout.addRow(SEARCH_CJK, &cjkCheckbox);
	QDialogButtonBox confirm(QDialogButtonBox::Ok | QDialogButtonBox::Help, &dialog);
	layout.addRow(&confirm);
	confirm.button(QDialogButtonBox::Ok)->setText(START_HOOK_SEARCH);
	confirm.button(QDialogButtonBox::Help)->setText(SETTINGS);
	connect(&confirm, &QDialogButtonBox::helpRequested, [&customSettings] { customSettings = true; });
	connect(&confirm, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
	connect(&confirm, &QDialogButtonBox::helpRequested, &dialog, &QDialog::accept);
	dialog.setWindowTitle(SEARCH_FOR_HOOKS);
	if (!dialog.exec()) return;

	if (customSettings)
	{
		QDialog dialog(this, Qt::WindowCloseButtonHint);
		QFormLayout layout(&dialog);
		QLineEdit patternInput(x64 ? "CC CC 48 89" : "CC CC 55 8B EC", &dialog);
		layout.addRow(SEARCH_PATTERN, &patternInput);
		for (auto [value, label] : Array<std::tuple<int&, const char*>>{
			{ sp.searchTime = 20000, SEARCH_DURATION },
			{ sp.offset = 2, PATTERN_OFFSET },
		})
		{
			auto spinBox = new QSpinBox(&dialog);
			spinBox->setMaximum(INT_MAX);
			spinBox->setValue(value);
			layout.addRow(label, spinBox);
			connect(spinBox, qOverload<int>(&QSpinBox::valueChanged), [&value] (int newValue) { value = newValue; });
		}
		for (auto [value, label] : Array<std::tuple<uintptr_t&, const char*>>{
			{ sp.minAddress = 0, MIN_ADDRESS },
			{ sp.maxAddress = -1ULL, MAX_ADDRESS },
			{ sp.padding = 0, STRING_OFFSET }
		})
		{
			auto input = new QLineEdit(QString::number(value, 16), &dialog);
			layout.addRow(label, input);
			connect(input, &QLineEdit::textEdited, [&value](QString input)
			{
				bool ok;
				if (uintptr_t newValue = input.toULongLong(&ok, 16); ok) value = newValue;
			});
		}
		QLineEdit filterInput(".", &dialog);
		layout.addRow(HOOK_SEARCH_FILTER, &filterInput);
		QPushButton startButton(START_HOOK_SEARCH, &dialog);
		layout.addWidget(&startButton);
		connect(&startButton, &QPushButton::clicked, &dialog, &QDialog::accept);
		if (!dialog.exec()) return;
		QByteArray pattern = QByteArray::fromHex(patternInput.text().replace("??", QString::number(XX, 16)).toUtf8());
		memcpy(sp.pattern, pattern.data(), sp.length = min(pattern.size(), 25));
		try { filter = std::wregex(S(filterInput.text())); } catch (std::regex_error) {}
	}
	else
	{
		// sp.length is 0 in this branch, so default will be used
		filter = cjkCheckbox.isChecked() ? std::wregex(L"[\\u3000-\\ua000]{4,}") : std::wregex(L"[\\u0020-\\u1000]{4,}");
	}

	auto hooks = std::make_shared<QString>();
	try
	{
		Host::FindHooks(processId, sp, [processId, hooks, filter](HookParam hp, const std::wstring& text)
		{
			if (std::regex_search(text, filter)) hooks->append(S(Util::GenerateCode(hp, processId)) + ": " + S(text) + "\n");
		});
	}
	catch (std::out_of_range) { return; }
	QString saveFile = QFileDialog::getSaveFileName(this, SAVE_SEARCH_RESULTS, "./Hooks.txt", TEXT_FILES);
	if (saveFile.isEmpty()) saveFile = "Hooks.txt";
	std::thread([hooks, saveFile]
	{
		for (int lastSize = 0; hooks->size() == 0 || hooks->size() != lastSize; Sleep(2000)) lastSize = hooks->size();
		QTextFile(saveFile, QIODevice::WriteOnly | QIODevice::Truncate).write(hooks->toUtf8());
		hooks->clear();
	}).detach();
}

void MainWindow::Settings()
{
	QDialog dialog(this, Qt::WindowCloseButtonHint);
	QSettings settings(CONFIG_FILE, QSettings::IniFormat, &dialog);
	QFormLayout layout(&dialog);
	QPushButton saveButton(SAVE_SETTINGS, &dialog);
	for (auto [value, label] : Array<std::tuple<bool&, const char*>>{
		{ TextThread::filterRepetition, FILTER_REPETITION },
		{ autoAttach, AUTO_ATTACH },
		{ autoAttachSavedOnly, ATTACH_SAVED_ONLY },
	})
	{
		auto checkBox = new QCheckBox(&dialog);
		checkBox->setChecked(value);
		layout.addRow(label, checkBox);
		connect(&saveButton, &QPushButton::clicked, [checkBox, label, &settings, &value] { settings.setValue(label, value = checkBox->isChecked()); });
	}
	for (auto [value, label] : Array<std::tuple<int&, const char*>>{
		{ TextThread::maxBufferSize, MAX_BUFFER_SIZE },
		{ TextThread::flushDelay, FLUSH_DELAY },
		{ Host::defaultCodepage, DEFAULT_CODEPAGE },
	})
	{
		auto spinBox = new QSpinBox(&dialog);
		spinBox->setMaximum(INT_MAX);
		spinBox->setValue(value);
		layout.addRow(label, spinBox);
		connect(&saveButton, &QPushButton::clicked, [spinBox, label, &settings, &value] { settings.setValue(label, value = spinBox->value()); });
	}
	layout.addWidget(&saveButton);
	connect(&saveButton, &QPushButton::clicked, &dialog, &QDialog::accept);
	dialog.setWindowTitle(SETTINGS);
	dialog.exec();
}

void MainWindow::Extensions()
{
	extenWindow->activateWindow();
	extenWindow->showNormal();
}

void MainWindow::ViewThread(int index)
{
	ui->ttCombo->setCurrentIndex(index);
	ui->textOutput->setPlainText(S((current = &Host::GetThread(ParseTextThreadString(ui->ttCombo->itemText(index))))->storage->c_str()));
	ui->textOutput->moveCursor(QTextCursor::End);
}

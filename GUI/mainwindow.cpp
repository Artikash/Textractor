#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "defs.h"
#include "module.h"
#include "extenwindow.h"
#include "../host/host.h"
#include "../host/hookcode.h"
#include "attachprocessdialog.h"
#include <shellapi.h>
#include <process.h>
#include <QRegularExpression>
#include <QStringListModel>
#include <QScrollBar>
#include <QMenu>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFontDialog>
#include <QHash>

extern const char* ATTACH;
extern const char* LAUNCH;
extern const char* CONFIG;
extern const char* DETACH;
extern const char* FORGET;
extern const char* ADD_HOOK;
extern const char* REMOVE_HOOKS;
extern const char* SAVE_HOOKS;
extern const char* SEARCH_FOR_HOOKS;
extern const char* SETTINGS;
extern const char* EXTENSIONS;
extern const char* FONT;
extern const char* SELECT_PROCESS;
extern const char* SELECT_PROCESS_INFO;
extern const char* FROM_COMPUTER;
extern const char* PROCESSES;
extern const char* CODE_INFODUMP;
extern const char* FAILED_TO_CREATE_CONFIG_FILE;
extern const char* HOOK_SEARCH_UNSTABLE_WARNING;
extern const char* HOOK_SEARCH_STARTING_VIEW_CONSOLE;
extern const char* SEARCH_CJK;
extern const char* SEARCH_PATTERN;
extern const char* SEARCH_DURATION;
extern const char* SEARCH_MODULE;
extern const char* PATTERN_OFFSET;
extern const char* MIN_ADDRESS;
extern const char* MAX_ADDRESS;
extern const char* STRING_OFFSET;
extern const char* MAX_HOOK_SEARCH_RECORDS;
extern const char* HOOK_SEARCH_FILTER;
extern const char* SEARCH_FOR_TEXT;
extern const char* TEXT;
extern const char* CODEPAGE;
extern const char* START_HOOK_SEARCH;
extern const char* SAVE_SEARCH_RESULTS;
extern const char* TEXT_FILES;
extern const char* DOUBLE_CLICK_TO_REMOVE_HOOK;
extern const char* SAVE_SETTINGS;
extern const char* USE_JP_LOCALE;
extern const char* FILTER_REPETITION;
extern const char* AUTO_ATTACH;
extern const char* ATTACH_SAVED_ONLY;
extern const char* SHOW_SYSTEM_PROCESSES;
extern const char* DEFAULT_CODEPAGE;
extern const char* FLUSH_DELAY;
extern const char* MAX_BUFFER_SIZE;
extern const char* MAX_HISTORY_SIZE;
extern const char* CONFIG_JP_LOCALE;
extern const wchar_t* ABOUT;
extern const wchar_t* CL_OPTIONS;
extern const wchar_t* LAUNCH_FAILED;
extern const wchar_t* INVALID_CODE;
extern const wchar_t* REPOSITORY;

namespace
{
	constexpr auto HOOK_SAVE_FILE = u8"SavedHooks.txt";
	constexpr auto GAME_SAVE_FILE = u8"SavedGames.txt";

	enum LaunchWithJapaneseLocale { PROMPT, ALWAYS, NEVER };

	Ui::MainWindow ui;
	std::atomic<DWORD> selectedProcessId = 0;
	ExtenWindow* extenWindow = nullptr;
	QString HookSaveFile = HOOK_SAVE_FILE;
	QString HookSaveFileProc = HOOK_SAVE_FILE;
	QString GameSaveFile = GAME_SAVE_FILE;
	std::wstring extenDefPath = L"./";
	concurrency::reader_writer_lock configFoldersMutex;
	std::unordered_map<DWORD, std::wstring> configFolders;
	std::unordered_set<DWORD> alreadyAttached;
	bool autoAttach = false, autoAttachSavedOnly = true;
	bool showSystemProcesses = false;
	uint64_t savedThreadCtx = 0, savedThreadCtx2 = 0;
	wchar_t savedThreadCode[1000] = {};
	TextThread* current = nullptr;
	MainWindow* This = nullptr;

	void FindHooks();

	QString TextThreadString(TextThread& thread)
	{
		return QString("%1:%2:%3:%4:%5: %6").arg(
			QString::number(thread.handle, 16),
			QString::number(thread.tp.processId, 16),
			QString::number(thread.tp.addr, 16),
			QString::number(thread.tp.ctx, 16),
			QString::number(thread.tp.ctx2, 16)
		).toUpper().arg(S(thread.name));
	}

	ThreadParam ParseTextThreadString(QString ttString)
	{
		auto threadParam = ttString.splitRef(":");
		return { threadParam[1].toUInt(nullptr, 16), threadParam[2].toULongLong(nullptr, 16), threadParam[3].toULongLong(nullptr, 16), threadParam[4].toULongLong(nullptr, 16) };
	}

	std::array<InfoForExtension, 20> GetSentenceInfo(TextThread& thread)
	{
		void (*AddText)(int64_t, const wchar_t*) = [](int64_t number, const wchar_t* text)
		{
			QMetaObject::invokeMethod(This, [number, text = std::wstring(text)] { if (TextThread* thread = Host::GetThread(number)) thread->Push(text.c_str()); });
		};
		void (*AddSentence)(int64_t, const wchar_t*) = [](int64_t number, const wchar_t* sentence)
		{
			// pointer from Host::GetThread may not stay valid unless on main thread
			QMetaObject::invokeMethod(This, [number, sentence = std::wstring(sentence)] { if (TextThread* thread = Host::GetThread(number)) thread->AddSentence(sentence); });
		};
		DWORD (*GetSelectedProcessId)() = [] { return selectedProcessId.load(); };

		concurrency::reader_writer_lock::scoped_lock_read readLock(configFoldersMutex);
		return
		{ {
		{ "current select", &thread == current },
		{ "text number", thread.handle },
		{ "process id", thread.tp.processId },
		{ "hook address", (int64_t)thread.tp.addr },
		{ "text handle", thread.handle },
		{ "text name", (int64_t)thread.name.c_str() },
		{ "config folder", thread.tp.processId ? (int64_t)configFolders.at(thread.tp.processId).c_str() : (int64_t)extenDefPath.c_str() },
		{ "add sentence", (int64_t)AddSentence },
		{ "add text", (int64_t)AddText },
		{ "get selected process id", (int64_t)GetSelectedProcessId },
		{ "void (*AddSentence)(int64_t number, const wchar_t* sentence)", (int64_t)AddSentence },
		{ "void (*AddText)(int64_t number, const wchar_t* text)", (int64_t)AddText },
		{ "DWORD (*GetSelectedProcessId)()", (int64_t)GetSelectedProcessId },
		{ nullptr, 0 } // nullptr marks end of info array
		} };
	}

	void AttachSavedProcesses()
	{
		std::unordered_set<std::wstring> attachTargets;
		if (autoAttach)
			for (auto process : QString(QTextFile(GAME_SAVE_FILE, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts))
				attachTargets.insert(S(process));
		if (autoAttachSavedOnly)
		{
			WIN32_FIND_DATA FindDirectory;
			HANDLE hFind;
			std::wstring  sPathFindDir = REPOSITORY;
			sPathFindDir += L"*";
			hFind = FindFirstFileW(sPathFindDir.c_str(), &FindDirectory);
			do
			{
				if (FindDirectory.dwFileAttributes == 16)	//Directory
					for (auto process : QString(QTextFile(S(REPOSITORY) + S(FindDirectory.cFileName) + u8"/" + HOOK_SAVE_FILE, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts))
						attachTargets.insert(S(process.split(" , ")[0]));
			} while (FindNextFile(hFind, &FindDirectory));
			FindClose(hFind);
		}

		if (!attachTargets.empty())
			for (auto [processId, processName] : GetAllProcesses())
				if (processName && attachTargets.count(processName.value()) > 0 && alreadyAttached.count(processId) == 0) Host::InjectProcess(processId);
	}

	std::optional<std::wstring> UserSelectedProcess()
	{
		QStringList savedProcesses = QString::fromUtf8(QTextFile(GAME_SAVE_FILE, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts);
		std::reverse(savedProcesses.begin(), savedProcesses.end());
		savedProcesses.removeDuplicates();
		savedProcesses.insert(1, FROM_COMPUTER);
		QString process = QInputDialog::getItem(This, SELECT_PROCESS, SELECT_PROCESS_INFO, savedProcesses, 0, true, &ok, Qt::WindowCloseButtonHint);
		if (process == FROM_COMPUTER) process = QDir::toNativeSeparators(QFileDialog::getOpenFileName(This, SELECT_PROCESS, "/", PROCESSES));
		if (ok && process.contains('\\')) return S(process);
		return {};
	}

	void ViewThread(int index)
	{
		ui.ttCombo->setCurrentIndex(index);
		ui.textOutput->setPlainText(sanitize(S((current = &Host::GetThread(ParseTextThreadString(ui.ttCombo->itemText(index))))->storage->c_str())));
		ui.textOutput->moveCursor(QTextCursor::End);
	}

	void AttachProcess()
	{
		QMultiHash<QString, DWORD> processesMap;
		std::vector<std::pair<QString, HICON>> processIcons;
		for (auto [processId, processName] : GetAllProcesses())
		{
			if (processName && (showSystemProcesses || processName->find(L":\\Windows\\") == std::string::npos))
			{
				QString fileName = QFileInfo(S(processName.value())).fileName();
				if (!processesMap.contains(fileName))
				{
					HICON bigIcon, smallIcon;
					ExtractIconExW(processName->c_str(), 0, &bigIcon, &smallIcon, 1);
					processIcons.push_back({ fileName, bigIcon ? bigIcon : smallIcon });
				}
				processesMap.insert(fileName, processId);
			}
		}
		std::sort(processIcons.begin(), processIcons.end(), [](auto one, auto two) { return QString::compare(one.first, two.first, Qt::CaseInsensitive) < 0; });

		AttachProcessDialog attachProcessDialog(This, processIcons);
		if (attachProcessDialog.exec())
		{
			QString process = attachProcessDialog.SelectedProcess();
			if (int processId = process.toInt(nullptr, 0)) Host::InjectProcess(processId);
			else for (int processId : processesMap.values(process)) Host::InjectProcess(processId);
		}
	}

	void LaunchProcess()
	{
		std::wstring process;
		if (auto selected = UserSelectedProcess()) process = selected.value();
		else return;
		std::wstring path = std::wstring(process).erase(process.rfind(L'\\'));

		PROCESS_INFORMATION info = {};
		auto useLocale = Settings().value(CONFIG_JP_LOCALE, PROMPT).toInt();
		if (!x64 && (useLocale == ALWAYS || (useLocale == PROMPT && QMessageBox::question(This, SELECT_PROCESS, USE_JP_LOCALE) == QMessageBox::Yes)))
		{
			if (HMODULE localeEmulator = LoadLibraryW(L"LoaderDll"))
			{
				// https://github.com/xupefei/Locale-Emulator/blob/aa99dec3b25708e676c90acf5fed9beaac319160/LEProc/LoaderWrapper.cs#L252
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

	void ConfigureProcess()
	{
 		// TODO: move this file into config folder (need to coordinate with texthook dll
		if (auto processName = GetModuleFilename(selectedProcessId)) if (int last = processName->rfind(L'\\') + 1)
		{
			std::wstring configFile = std::wstring(processName.value()).replace(last, std::string::npos, GAME_CONFIG_FILE);
			if (!std::filesystem::exists(configFile)) QTextFile(S(configFile), QFile::WriteOnly).write("see https://github.com/Artikash/Textractor/wiki/Game-configuration-file");
			if (std::filesystem::exists(configFile)) _wspawnlp(_P_DETACH, L"notepad", L"notepad", configFile.c_str(), NULL);
			else QMessageBox::critical(This, CONFIG, QString(FAILED_TO_CREATE_CONFIG_FILE).arg(S(configFile)));
		}
	}

	void DetachProcess()
	{
		try { Host::DetachProcess(selectedProcessId); }
		catch (std::out_of_range) {}
	}

	void ForgetProcess()
	{
		auto processName = GetModuleFilename(selectedProcessId);
		if (!processName) processName = UserSelectedProcess();
		DetachProcess();
		if (!processName) return;
		for (auto file : { GameSaveFile, HookSaveFile, HookSaveFileProc })
		{
			QStringList lines = QString::fromUtf8(QTextFile(file, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts);
			lines.erase(std::remove_if(lines.begin(), lines.end(), [&](const QString& line) { return line.contains(S(processName.value())); }), lines.end());
			QTextFile(file, QIODevice::WriteOnly | QIODevice::Truncate).write(lines.join("\n").append("\n").toUtf8());
		}
	}

	void AddHook(QString hook)
	{
		if (QString hookCode = QInputDialog::getText(This, ADD_HOOK, CODE_INFODUMP, QLineEdit::Normal, hook, &ok, Qt::WindowCloseButtonHint); ok)
			if (hookCode.startsWith("S") || hookCode.startsWith("/S")) FindHooks(); // backwards compatibility for old hook search UX
			else if (auto hp = HookCode::Parse(S(hookCode))) try { Host::InsertHook(selectedProcessId, hp.value()); } catch (std::out_of_range) {}
			else Host::AddConsoleOutput(INVALID_CODE);
	}

	void AddHook()
	{
		AddHook("");
	}

	void RemoveHooks()
	{
		DWORD processId = selectedProcessId;
		std::unordered_map<uint64_t, HookParam> hooks;
		for (int i = 0; i < ui.ttCombo->count(); ++i)
		{
			ThreadParam tp = ParseTextThreadString(ui.ttCombo->itemText(i));
			if (tp.processId == selectedProcessId) hooks[tp.addr] = Host::GetThread(tp).hp;
		}
		auto hookList = new QListWidget(This);
		hookList->setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint);
		hookList->setAttribute(Qt::WA_DeleteOnClose);
		hookList->setMinimumSize({ 300, 50 });
		hookList->setWindowTitle(DOUBLE_CLICK_TO_REMOVE_HOOK);
		for (auto [address, hp] : hooks) new QListWidgetItem(QString(hp.name) + "@" + QString::number(address, 16), hookList);
		QObject::connect(hookList, &QListWidget::itemDoubleClicked, [processId, hookList](QListWidgetItem* item)
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

	void SaveHooks()
	{
		auto processName = GetModuleFilename(selectedProcessId);
		if (!processName) return;
		QHash<uint64_t, QString> hookCodes;
		for (int i = 0; i < ui.ttCombo->count(); ++i)
		{
			ThreadParam tp = ParseTextThreadString(ui.ttCombo->itemText(i));
			if (tp.processId == selectedProcessId)
			{
				HookParam hp = Host::GetThread(tp).hp;
				if (!(hp.type & HOOK_ENGINE)) hookCodes[tp.addr] = S(HookCode::Generate(hp, tp.processId));
			}
		}
		auto hookInfo = QStringList() << S(processName.value()) << hookCodes.values();
		ThreadParam tp = current->tp;
		if (tp.processId == selectedProcessId) hookInfo << QString("|%1:%2:%3").arg(tp.ctx).arg(tp.ctx2).arg(S(HookCode::Generate(current->hp, tp.processId)));
		QTextFile(HookSaveFileProc, QIODevice::WriteOnly | QIODevice::Append).write((hookInfo.join(" , ") + "\n").toUtf8());
	}

	void FindHooks()
	{
		QMessageBox::information(This, SEARCH_FOR_HOOKS, HOOK_SEARCH_UNSTABLE_WARNING);

		DWORD processId = selectedProcessId;
		SearchParam sp = {};
		sp.codepage = Host::defaultCodepage;
		bool searchForText = false, customSettings = false;
		QRegularExpression filter(".", QRegularExpression::UseUnicodePropertiesOption | QRegularExpression::DotMatchesEverythingOption);

		QDialog dialog(This, Qt::WindowCloseButtonHint);
		QFormLayout layout(&dialog);
		QCheckBox asianCheck(&dialog);
		layout.addRow(SEARCH_CJK, &asianCheck);
		QDialogButtonBox confirm(QDialogButtonBox::Ok | QDialogButtonBox::Help | QDialogButtonBox::Retry, &dialog);
		layout.addRow(&confirm);
		confirm.button(QDialogButtonBox::Ok)->setText(START_HOOK_SEARCH);
		confirm.button(QDialogButtonBox::Retry)->setText(SEARCH_FOR_TEXT);
		confirm.button(QDialogButtonBox::Help)->setText(SETTINGS);
		QObject::connect(&confirm, &QDialogButtonBox::clicked, [&](QAbstractButton* button)
		{
			if (button == confirm.button(QDialogButtonBox::Retry)) searchForText = true;
			if (button == confirm.button(QDialogButtonBox::Help)) customSettings = true;
			dialog.accept();
		});
		dialog.setWindowTitle(SEARCH_FOR_HOOKS);
		if (!dialog.exec()) return;

		if (searchForText)
		{
			QDialog dialog(This, Qt::WindowCloseButtonHint);
			QFormLayout layout(&dialog);
			QLineEdit textEdit(&dialog);
			layout.addRow(TEXT, &textEdit);
			QSpinBox codepageSpin(&dialog);
			codepageSpin.setMaximum(INT_MAX);
			codepageSpin.setValue(sp.codepage);
			layout.addRow(CODEPAGE, &codepageSpin);
			QDialogButtonBox confirm(QDialogButtonBox::Ok);
			QObject::connect(&confirm, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
			layout.addRow(&confirm);
			if (!dialog.exec()) return;
			wcsncpy_s(sp.text, S(textEdit.text()).c_str(), PATTERN_SIZE - 1);
			try
			{
				Host::FindHooks(selectedProcessId, sp);
				ViewThread(0);
			} catch (std::out_of_range) {}
			return;
		}

		filter.setPattern(asianCheck.isChecked() ? "[\\x{3000}-\\x{a000}]{4,}" : "[\\x{0020}-\\x{1000}]{4,}");
		if (customSettings)
		{
			QDialog dialog(This, Qt::WindowCloseButtonHint);
			QFormLayout layout(&dialog);
			QLineEdit patternEdit(x64 ? "CC CC 48 89" : "55 8B EC", &dialog);
			assert(QByteArray::fromHex(patternEdit.text().toUtf8()) == QByteArray((const char*)sp.pattern, sp.length));
			layout.addRow(SEARCH_PATTERN, &patternEdit);
			for (auto [value, label] : Array<int&, const char*>{
				{ sp.searchTime, SEARCH_DURATION },
				{ sp.offset, PATTERN_OFFSET },
				{ sp.maxRecords, MAX_HOOK_SEARCH_RECORDS },
				{ sp.codepage, CODEPAGE },
			})
			{
				auto spinBox = new QSpinBox(&dialog);
				spinBox->setMaximum(INT_MAX);
				spinBox->setValue(value);
				layout.addRow(label, spinBox);
				QObject::connect(spinBox, qOverload<int>(&QSpinBox::valueChanged), [&value](int newValue) { value = newValue; });
			}
			QLineEdit boundEdit(QFileInfo(S(GetModuleFilename(selectedProcessId).value_or(L""))).fileName(), &dialog);
			layout.addRow(SEARCH_MODULE, &boundEdit);
			for (auto [value, label] : Array<uintptr_t&, const char*>{
				{ sp.minAddress, MIN_ADDRESS },
				{ sp.maxAddress, MAX_ADDRESS },
				{ sp.padding, STRING_OFFSET },
			})
			{
				auto edit = new QLineEdit(QString::number(value, 16), &dialog);
				layout.addRow(label, edit);
				QObject::connect(edit, &QLineEdit::textEdited, [&value](QString text) { if (uintptr_t newValue = text.toULongLong(&ok, 16); ok) value = newValue; });
			}
			QLineEdit filterEdit(filter.pattern(), &dialog);
			layout.addRow(HOOK_SEARCH_FILTER, &filterEdit);
			QPushButton startButton(START_HOOK_SEARCH, &dialog);
			layout.addWidget(&startButton);
			QObject::connect(&startButton, &QPushButton::clicked, &dialog, &QDialog::accept);
			if (!dialog.exec()) return;
			if (patternEdit.text().contains('.'))
			{
				wcsncpy_s(sp.exportModule, S(patternEdit.text()).c_str(), MAX_MODULE_SIZE - 1);
				sp.length = 1;
			}
			else
			{
				QByteArray pattern = QByteArray::fromHex(patternEdit.text().replace("??", QString::number(XX, 16)).toUtf8());
				memcpy(sp.pattern, pattern.data(), sp.length = min(pattern.size(), PATTERN_SIZE));
			}
			wcsncpy_s(sp.boundaryModule, S(boundEdit.text()).c_str(), MAX_MODULE_SIZE - 1);
			filter.setPattern(filterEdit.text());
			if (!filter.isValid()) filter.setPattern(".");
		}
		else
		{
			sp.length = 0; // use default
		}
		filter.optimize();

		auto hooks = std::make_shared<QStringList>();
		try
		{
			Host::FindHooks(processId, sp,
				[hooks, filter](HookParam hp, std::wstring text) { if (filter.match(S(text)).hasMatch()) *hooks << sanitize(S(HookCode::Generate(hp) + L" => " + text)); });
		}
		catch (std::out_of_range) { return; }
		ViewThread(0);
		std::thread([hooks]
		{
			for (int lastSize = 0; hooks->size() == 0 || hooks->size() != lastSize; Sleep(2000)) lastSize = hooks->size();

			QString saveFileName;
			QMetaObject::invokeMethod(This, [&]
			{
				auto hookList = new QListView(This);
				hookList->setWindowFlags(Qt::Window | Qt::WindowCloseButtonHint);
				hookList->setAttribute(Qt::WA_DeleteOnClose);
				hookList->resize({ 750, 300 });
				hookList->setWindowTitle(SEARCH_FOR_HOOKS);
				if (hooks->size() > 5'000)
				{
					hookList->setUniformItemSizes(true); // they aren't actually uniform, but this improves performance
					hooks->push_back(QString(2000, '-')); // dumb hack: with uniform item sizes, the last item is assumed to be the largest
				}
				hookList->setModel(new QStringListModel(*hooks, hookList));
				QObject::connect(hookList, &QListView::clicked, [](QModelIndex i) { AddHook(i.data().toString().split(" => ")[0]); });
				hookList->show();

				saveFileName = QFileDialog::getSaveFileName(This, SAVE_SEARCH_RESULTS, "./results.txt", TEXT_FILES);
			}, Qt::BlockingQueuedConnection);
			if (!saveFileName.isEmpty())
			{
				QTextFile saveFile(saveFileName, QIODevice::WriteOnly | QIODevice::Truncate);
				for (auto hook = hooks->cbegin(); hook != hooks->cend(); ++hook) saveFile.write(hook->toUtf8().append('\n')); // QStringList::begin() makes a copy
			}
			hooks->clear();
		}).detach();
		QMessageBox::information(This, SEARCH_FOR_HOOKS, HOOK_SEARCH_STARTING_VIEW_CONSOLE);
	}

	void OpenSettings()
	{
		QDialog dialog(This, Qt::WindowCloseButtonHint);
		Settings settings(&dialog);
		QFormLayout layout(&dialog);
		QPushButton saveButton(SAVE_SETTINGS, &dialog);
		for (auto [value, label] : Array<bool&, const char*>{
			{ TextThread::filterRepetition, FILTER_REPETITION },
			{ autoAttach, AUTO_ATTACH },
			{ autoAttachSavedOnly, ATTACH_SAVED_ONLY },
			{ showSystemProcesses, SHOW_SYSTEM_PROCESSES },
		})
		{
			auto checkBox = new QCheckBox(&dialog);
			checkBox->setChecked(value);
			layout.addRow(label, checkBox);
			QObject::connect(&saveButton, &QPushButton::clicked, [checkBox, label, &settings, &value] { settings.setValue(label, value = checkBox->isChecked()); });
		}
		for (auto [value, label] : Array<int&, const char*>{
			{ TextThread::maxBufferSize, MAX_BUFFER_SIZE },
			{ TextThread::flushDelay, FLUSH_DELAY },
			{ TextThread::maxHistorySize, MAX_HISTORY_SIZE },
			{ Host::defaultCodepage, DEFAULT_CODEPAGE },
		})
		{
			auto spinBox = new QSpinBox(&dialog);
			spinBox->setMaximum(INT_MAX);
			spinBox->setValue(value);
			layout.addRow(label, spinBox);
			QObject::connect(&saveButton, &QPushButton::clicked, [spinBox, label, &settings, &value] { settings.setValue(label, value = spinBox->value()); });
		}
		QComboBox localeCombo(&dialog);
		assert(PROMPT == 0 && ALWAYS == 1 && NEVER == 2);
		localeCombo.addItems({ { "Prompt", "Always", "Never" } });
		localeCombo.setCurrentIndex(settings.value(CONFIG_JP_LOCALE, PROMPT).toInt());
		layout.addRow(CONFIG_JP_LOCALE, &localeCombo);
		QObject::connect(&localeCombo, qOverload<int>(&QComboBox::activated), [&settings](int i) { settings.setValue(CONFIG_JP_LOCALE, i); });
		layout.addWidget(&saveButton);
		QObject::connect(&saveButton, &QPushButton::clicked, &dialog, &QDialog::accept);
		dialog.setWindowTitle(SETTINGS);
		dialog.exec();
	}

	void Extensions()
	{
		extenWindow->activateWindow();
		extenWindow->showNormal();
	}

	void SetOutputFont(QString fontString)
	{
		QFont font = ui.textOutput->font();
		font.fromString(fontString);
		font.setStyleStrategy(QFont::NoFontMerging);
		ui.textOutput->setFont(font);
		Settings().setValue(FONT, font.toString());
	}

	void ProcessConnected(DWORD processId)
	{
		alreadyAttached.insert(processId);

		QString process = S(GetModuleFilename(processId).value_or(L"???"));
		QMetaObject::invokeMethod(This, [process, processId]
		{
			ui.processCombo->addItem(QString::number(processId, 16).toUpper() + ": " + QFileInfo(process).fileName());
		});
		if (process == "???") return;

		std::wstring repositoryDir;
		repositoryDir = REPOSITORY;
		repositoryDir += std::filesystem::path(S(process)).parent_path().filename();
		repositoryDir += L"("; 
		repositoryDir += std::filesystem::path(S(process)).filename().replace_extension("");
		repositoryDir += L")_" + std::to_wstring(std::hash<std::wstring_view>()(S(process)));
		repositoryDir += L"/";
		if (!std::filesystem::exists(REPOSITORY)) CreateDirectoryW(REPOSITORY, nullptr);
		if (!std::filesystem::exists(repositoryDir)) CreateDirectoryW(repositoryDir.c_str(), nullptr);
		std::scoped_lock writeLock(configFoldersMutex);
		configFolders[processId] = repositoryDir;
		HookSaveFileProc = S(repositoryDir) + HOOK_SAVE_FILE;

		loadExtensions(repositoryDir);

		// This does add (potentially tons of) duplicates to the file, but as long as I don't perform Ω(N^2) operations it shouldn't be an issue
		QTextFile(GAME_SAVE_FILE, QIODevice::WriteOnly | QIODevice::Append).write((process + "\n").toUtf8());

		QStringList allProcesses = QString(QTextFile(HookSaveFileProc, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts);
		allProcesses += QString(QTextFile(HOOK_SAVE_FILE, QIODevice::ReadOnly).readAll()).split("\n", QString::SkipEmptyParts); //for hooks saved without config folder
		auto hookList = std::find_if(allProcesses.rbegin(), allProcesses.rend(), [&](QString hookList) { return hookList.contains(process); });
		if (hookList != allProcesses.rend())
			for (auto hookInfo : hookList->split(" , "))
				if (auto hp = HookCode::Parse(S(hookInfo))) Host::InsertHook(processId, hp.value());
				else swscanf_s(S(hookInfo).c_str(), L"|%I64d:%I64d:%[^\n]", &savedThreadCtx, &savedThreadCtx2, savedThreadCode, (unsigned)std::size(savedThreadCode));
	}

	void ProcessDisconnected(DWORD processId)
	{
		QMetaObject::invokeMethod(This, [processId]
		{
			ui.processCombo->removeItem(ui.processCombo->findText(QString::number(processId, 16).toUpper() + ":", Qt::MatchStartsWith));
		}, Qt::BlockingQueuedConnection);
		HookSaveFileProc = HOOK_SAVE_FILE;
		loadExtensions(extenDefPath);
	}

	void ThreadAdded(TextThread& thread)
	{
		std::wstring threadCode = HookCode::Generate(thread.hp, thread.tp.processId);
		bool savedMatch = (savedThreadCtx & 0xFFFF) == (thread.tp.ctx & 0xFFFF) && savedThreadCtx2 == thread.tp.ctx2 && savedThreadCode == threadCode;
		if (savedMatch)
		{
			savedThreadCtx = savedThreadCtx2 = savedThreadCode[0] = 0;
			current = &thread;
		}
		QMetaObject::invokeMethod(This, [savedMatch, ttString = TextThreadString(thread) + S(FormatString(L" (%s)", threadCode))]
		{
			ui.ttCombo->addItem(ttString);
			if (savedMatch) ViewThread(ui.ttCombo->count() - 1);
		});
	}

	void ThreadRemoved(TextThread& thread)
	{
		QMetaObject::invokeMethod(This, [ttString = TextThreadString(thread)]
		{
			int threadIndex = ui.ttCombo->findText(ttString, Qt::MatchStartsWith);
			if (threadIndex == ui.ttCombo->currentIndex())	ViewThread(0);
			ui.ttCombo->removeItem(threadIndex);
		}, Qt::BlockingQueuedConnection);
	}

	bool SentenceReceived(TextThread& thread, std::wstring& sentence)
	{
		for (int i = 0; i < sentence.size(); ++i) if (sentence[i] == '\r' && sentence[i + 1] == '\n') sentence[i] = 0x200b; // for some reason \r appears as newline - no need to double
		if (!DispatchSentenceToExtensions(sentence, GetSentenceInfo(thread).data())) return false;
		sentence += L'\n';
		if (&thread == current) QMetaObject::invokeMethod(This, [sentence = S(sentence)]() mutable
		{
			sanitize(sentence);
			auto scrollbar = ui.textOutput->verticalScrollBar();
			bool atBottom = scrollbar->value() + 3 > scrollbar->maximum() || (double)scrollbar->value() / scrollbar->maximum() > 0.975; // arbitrary
			QTextCursor cursor(ui.textOutput->document());
			cursor.movePosition(QTextCursor::End);
			cursor.insertText(sentence);
			if (atBottom) scrollbar->setValue(scrollbar->maximum());
		});
		return true;
	}

	void OutputContextMenu(QPoint point)
	{
		std::unique_ptr<QMenu> menu(ui.textOutput->createStandardContextMenu());
		menu->addAction(FONT, [] { if (QString font = QFontDialog::getFont(&ok, ui.textOutput->font(), This, FONT).toString(); ok) SetOutputFont(font); });
		menu->exec(ui.textOutput->mapToGlobal(point));
	}

	void CopyUnlessMouseDown()
	{
		if (!(QApplication::mouseButtons() & Qt::LeftButton)) ui.textOutput->copy();
	}
}

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
	This = this;
	ui.setupUi(this);
	extenWindow = new ExtenWindow(this);
	for (auto [text, slot] : Array<const char*, void(&)()>{
		{ ATTACH, AttachProcess },
		{ LAUNCH, LaunchProcess },
		{ CONFIG, ConfigureProcess },
		{ DETACH, DetachProcess },
		{ FORGET, ForgetProcess },
		{ ADD_HOOK, AddHook },
		{ REMOVE_HOOKS, RemoveHooks },
		{ SAVE_HOOKS, SaveHooks },
		{ SEARCH_FOR_HOOKS, FindHooks },
		{ SETTINGS, OpenSettings },
		{ EXTENSIONS, Extensions }
	})
	{
		auto button = new QPushButton(text, ui.processFrame);
		connect(button, &QPushButton::clicked, slot);
		ui.processLayout->addWidget(button);
	}
	ui.processLayout->addItem(new QSpacerItem(0, 0, QSizePolicy::Minimum, QSizePolicy::Expanding));

	connect(ui.processCombo, qOverload<int>(&QComboBox::currentIndexChanged), [] { selectedProcessId = ui.processCombo->currentText().split(":")[0].toULong(nullptr, 16); });
	connect(ui.ttCombo, qOverload<int>(&QComboBox::activated), this, ViewThread);
	connect(ui.textOutput, &QPlainTextEdit::selectionChanged, this, CopyUnlessMouseDown);
	connect(ui.textOutput, &QPlainTextEdit::customContextMenuRequested, this, OutputContextMenu);

	Settings settings;
	if (settings.contains(WINDOW) && QApplication::screenAt(settings.value(WINDOW).toRect().center())) setGeometry(settings.value(WINDOW).toRect());
	SetOutputFont(settings.value(FONT, ui.textOutput->font().toString()).toString());
	TextThread::filterRepetition = settings.value(FILTER_REPETITION, TextThread::filterRepetition).toBool();
	autoAttach = settings.value(AUTO_ATTACH, autoAttach).toBool();
	autoAttachSavedOnly = settings.value(ATTACH_SAVED_ONLY, autoAttachSavedOnly).toBool();
	showSystemProcesses = settings.value(SHOW_SYSTEM_PROCESSES, showSystemProcesses).toBool();
	TextThread::flushDelay = settings.value(FLUSH_DELAY, TextThread::flushDelay).toInt();
	TextThread::maxBufferSize = settings.value(MAX_BUFFER_SIZE, TextThread::maxBufferSize).toInt();
	TextThread::maxHistorySize = settings.value(MAX_HISTORY_SIZE, TextThread::maxHistorySize).toInt();
	Host::defaultCodepage = settings.value(DEFAULT_CODEPAGE, Host::defaultCodepage).toInt();

	Host::Start(ProcessConnected, ProcessDisconnected, ThreadAdded, ThreadRemoved, SentenceReceived);
	current = &Host::GetThread(Host::console);
	Host::AddConsoleOutput(ABOUT);

	AttachConsole(ATTACH_PARENT_PROCESS);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), CL_OPTIONS, wcslen(CL_OPTIONS), DUMMY, NULL);
	auto processes = GetAllProcesses();
	int argc;
	std::unique_ptr<LPWSTR[], Functor<LocalFree>> argv(CommandLineToArgvW(GetCommandLineW(), &argc));
	for (int i = 0; i < argc; ++i)
		if (std::wstring arg = argv[i]; arg[0] == L'/' || arg[0] == L'-')
		{
			if (arg[1] == L'p' || arg[1] == L'P')
				if (DWORD processId = wcstoul(arg.substr(2).c_str(), nullptr, 0)) Host::InjectProcess(processId);
				else for (auto [processId, processName] : processes)
					if (processName.value_or(L"").find(L"\\" + arg.substr(2)) != std::string::npos) Host::InjectProcess(processId);
			if (arg[1] == L'e' || arg[1] == L'E')
			{
				extenDefPath = arg.substr(2);
				extenDefPath += L"/";
				if (std::filesystem::exists(extenDefPath)) loadExtensions(extenDefPath);
				else WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), L"\n\n-e path not found!", 20, DUMMY, NULL);
			}
		}

	std::thread([] { for (; ; Sleep(10000)) AttachSavedProcesses(); }).detach();
}

MainWindow::~MainWindow()
{
	Settings().setValue(WINDOW, geometry());
	CleanupExtensions();
	SetErrorMode(SEM_NOGPFAULTERRORBOX);
	ExitProcess(0);
}

void MainWindow::closeEvent(QCloseEvent*)
{
	QApplication::quit(); // Need to do this to kill any windows that might've been made by extensions
}

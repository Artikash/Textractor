#include "extenwindow.h"
#include "ui_extenwindow.h"
#include <QMenu>
#include <QFileDialog>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>

extern const char* EXTENSIONS;
extern const char* ADD_EXTENSION;
extern const char* REMOVE_EXTENSION;
extern const char* INVALID_EXTENSION;
extern const char* CONFIRM_EXTENSION_OVERWRITE;
extern const char* EXTENSION_WRITE_ERROR;
extern const char* EXTEN_WINDOW_INSTRUCTIONS;

namespace
{
	constexpr auto EXTEN_SAVE_FILE = u8"SavedExtensions.txt";
	constexpr auto DEFAULT_EXTENSIONS = u8"Remove Repeated Characters>Regex Filter>Copy to Clipboard>Google Translate>Extra Window>Extra Newlines";

	struct Extension
	{
		std::wstring name;
		wchar_t* (*callback)(wchar_t*, const InfoForExtension*);
	};

	Ui::ExtenWindow ui;
	concurrency::reader_writer_lock extenMutex;
	std::vector<Extension> extensions;
	ExtenWindow* This = nullptr;

	bool Load(QString extenName)
	{
		if (extenName.endsWith(".dll")) extenName.chop(4);
		if (extenName.endsWith(".xdll")) extenName.chop(5);
		if (!QFile::exists(extenName + ".xdll")) QFile::copy(extenName + ".dll", extenName + ".xdll");
		// Extension must export "OnNewSentence"
		if (QTextFile(extenName + ".xdll", QIODevice::ReadOnly).readAll().contains("OnNewSentence"))
		{
			if (HMODULE module = LoadLibraryW(S(extenName + ".xdll").c_str()))
			{
				if (auto callback = (decltype(Extension::callback))GetProcAddress(module, "OnNewSentence"))
				{
					std::scoped_lock lock(extenMutex);
					extensions.push_back({ S(extenName), callback });
					return true;
				}
				FreeLibrary(module);
			}
		}
		return false;
	}

	void Unload(int index)
	{
		std::scoped_lock lock(extenMutex);
		FreeLibrary(GetModuleHandleW((extensions.at(index).name + L".xdll").c_str()));
		extensions.erase(extensions.begin() + index);
	}

	void Reorder(QStringList extenNames)
	{
		std::scoped_lock lock(extenMutex);
		std::vector<Extension> extensions;
		for (auto extenName : extenNames)
			extensions.push_back(*std::find_if(::extensions.begin(), ::extensions.end(), [&](Extension extension) { return extension.name == S(extenName); }));
		::extensions = extensions;
	}

	void Sync()
	{
		ui.extenList->clear();
		QTextFile extenSaveFile(EXTEN_SAVE_FILE, QIODevice::WriteOnly | QIODevice::Truncate);
		concurrency::reader_writer_lock::scoped_lock_read readLock(extenMutex);
		for (auto extension : extensions)
		{
			ui.extenList->addItem(S(extension.name));
			extenSaveFile.write((S(extension.name) + ">").toUtf8());
		}
	}

	void Add(QFileInfo extenFile)
	{
		if (extenFile.suffix() == "dll" || extenFile.suffix() == "xdll")
		{
			if (extenFile.absolutePath() != QDir::currentPath())
			{
				if (QFile::exists(extenFile.fileName()) && QMessageBox::question(This, EXTENSIONS, CONFIRM_EXTENSION_OVERWRITE) == QMessageBox::Yes) QFile::remove(extenFile.fileName());
				if (!QFile::copy(extenFile.absoluteFilePath(), extenFile.fileName())) QMessageBox::warning(This, EXTENSIONS, EXTENSION_WRITE_ERROR);
			}
			if (Load(extenFile.fileName())) return Sync();
		}
		QMessageBox::information(This, EXTENSIONS, QString(INVALID_EXTENSION).arg(extenFile.fileName()));
	}

	void Delete()
	{
		if (ui.extenList->currentItem())
		{
			Unload(ui.extenList->currentIndex().row());
			Sync();
		}
	}

	void ContextMenu(QPoint point)
	{
		QAction addExtension(ADD_EXTENSION), removeExtension(REMOVE_EXTENSION);
		if (auto action = QMenu::exec({ &addExtension, &removeExtension }, ui.extenList->mapToGlobal(point), nullptr, This))
			if (action == &removeExtension) Delete();
			else if (QString extenFile = QFileDialog::getOpenFileName(This, ADD_EXTENSION, ".", EXTENSIONS + QString(" (*.xdll);;Libraries (*.dll)")); !extenFile.isEmpty()) Add(extenFile);
	}
}

bool DispatchSentenceToExtensions(std::wstring& sentence, const InfoForExtension* sentenceInfo)
{
	wchar_t* sentenceBuffer = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, (sentence.size() + 1) * sizeof(wchar_t));
	wcscpy_s(sentenceBuffer, sentence.size() + 1, sentence.c_str());
	concurrency::reader_writer_lock::scoped_lock_read readLock(extenMutex);
	for (const auto& extension : extensions)
		if (!*(sentenceBuffer = extension.callback(sentenceBuffer, sentenceInfo))) break;
	sentence = sentenceBuffer;
	HeapFree(GetProcessHeap(), 0, sentenceBuffer);
	return !sentence.empty();
}

void CleanupExtensions()
{
	std::scoped_lock lock(extenMutex);
	for (auto extension : extensions) FreeLibrary(GetModuleHandleW((extension.name + L".xdll").c_str()));
	extensions.clear();
}

ExtenWindow::ExtenWindow(QWidget* parent) : QMainWindow(parent, Qt::WindowCloseButtonHint)
{
	This = this;
	ui.setupUi(this);
	ui.vboxLayout->addWidget(new QLabel(EXTEN_WINDOW_INSTRUCTIONS, this));
	setWindowTitle(EXTENSIONS);

	connect(ui.extenList, &QListWidget::customContextMenuRequested, ContextMenu);
	ui.extenList->installEventFilter(this);

	if (!QFile::exists(EXTEN_SAVE_FILE)) QTextFile(EXTEN_SAVE_FILE, QIODevice::WriteOnly).write(DEFAULT_EXTENSIONS);
	for (auto extenName : QString(QTextFile(EXTEN_SAVE_FILE, QIODevice::ReadOnly).readAll()).split(">")) Load(extenName);
	Sync();
}

bool ExtenWindow::eventFilter(QObject* target, QEvent* event)
{
	// https://stackoverflow.com/questions/1224432/how-do-i-respond-to-an-internal-drag-and-drop-operation-using-a-qlistwidget/1528215
	if (event->type() == QEvent::ChildRemoved)
	{
		QStringList extenNames;
		for (int i = 0; i < ui.extenList->count(); ++i) extenNames.push_back(ui.extenList->item(i)->text());
		Reorder(extenNames);
		Sync();
	}
	return false;
}

void ExtenWindow::keyPressEvent(QKeyEvent* event)
{
	if (event->key() == Qt::Key_Delete) Delete();
}

void ExtenWindow::dragEnterEvent(QDragEnterEvent* event)
{
	event->acceptProposedAction();
}

void ExtenWindow::dropEvent(QDropEvent* event)
{
	for (auto file : event->mimeData()->urls()) Add(file.toLocalFile());
}

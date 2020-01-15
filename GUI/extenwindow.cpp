#include "extenwindow.h"
#include "ui_extenwindow.h"
#include "defs.h"
#include <concrt.h>
#include <QMenu>
#include <QFileDialog>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>

extern const char* EXTENSIONS;
extern const char* ADD_EXTENSION;
extern const char* INVALID_EXTENSION;
extern const char* CONFIRM_EXTENSION_OVERWRITE;
extern const char* EXTENSION_WRITE_ERROR;
extern const char* EXTEN_WINDOW_INSTRUCTIONS;

constexpr auto DEFAULT_EXTENSIONS = u8"Remove Repeated Characters>Remove Repeated Phrases>Regex Filter>Copy to Clipboard>Bing Translate>Extra Window>Extra Newlines";

namespace
{
	struct Extension
	{
		std::wstring name;
		wchar_t* (*callback)(wchar_t*, const InfoForExtension*);
	};

	concurrency::reader_writer_lock extenMutex;
	std::vector<Extension> extensions;

	bool Load(QString extenName)
	{
		// Extension is dll and exports "OnNewSentence"
		if (QTextFile(extenName + ".dll", QIODevice::ReadOnly).readAll().contains("OnNewSentence"))
		{
			if (HMODULE module = LoadLibraryW(S(extenName + ".dll").c_str()))
			{
				if (auto callback = (decltype(Extension::callback))GetProcAddress(module, "OnNewSentence"))
				{
					std::scoped_lock writeLock(extenMutex);
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
		std::scoped_lock writeLock(extenMutex);
		FreeLibrary(GetModuleHandleW((extensions.at(index).name + L".dll").c_str()));
		extensions.erase(extensions.begin() + index);
	}

	void Reorder(QStringList extenNames)
	{
		std::scoped_lock writeLock(extenMutex);
		std::vector<Extension> extensions;
		for (auto extenName : extenNames)
			extensions.push_back(*std::find_if(::extensions.begin(), ::extensions.end(), [&](auto extension) { return extension.name == S(extenName); }));
		::extensions = extensions;
	}
}

bool DispatchSentenceToExtensions(std::wstring& sentence, const InfoForExtension* sentenceInfo)
{
	wchar_t* sentenceBuffer = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, (sentence.size() + 1) * sizeof(wchar_t));
	wcscpy_s(sentenceBuffer, sentence.size() + 1, sentence.c_str());
	concurrency::reader_writer_lock::scoped_lock_read readLock(extenMutex);
	for (const auto& extension : extensions)
		if (*(sentenceBuffer = extension.callback(sentenceBuffer, sentenceInfo)) == L'\0') break;
	sentence = sentenceBuffer;
	HeapFree(GetProcessHeap(), 0, sentenceBuffer);
	return !sentence.empty();
}

void CleanupExtensions()
{
	std::scoped_lock writeLock(extenMutex);
	for (auto extension : extensions) FreeLibrary(GetModuleHandleW((extension.name + L".dll").c_str()));
	extensions.clear();
}

ExtenWindow::ExtenWindow(QWidget* parent) :
	QMainWindow(parent, Qt::WindowCloseButtonHint),
	ui(new Ui::ExtenWindow)
{
	ui->setupUi(this);

	connect(ui->extenList, &QListWidget::customContextMenuRequested, [this](QPoint point)
	{
		if (QMenu(this).exec({ std::make_unique<QAction>(ADD_EXTENSION).get() }, ui->extenList->mapToGlobal(point)))
			if (QString extenFile = QFileDialog::getOpenFileName(this, ADD_EXTENSION, ".", EXTENSIONS + QString(" (*.dll)")); !extenFile.isEmpty()) Add(extenFile);
	});

	ui->vboxLayout->addWidget(new QLabel(EXTEN_WINDOW_INSTRUCTIONS, this));
	setWindowTitle(EXTENSIONS);

	ui->extenList->installEventFilter(this);

	if (!QFile::exists(EXTEN_SAVE_FILE)) QTextFile(EXTEN_SAVE_FILE, QIODevice::WriteOnly).write(DEFAULT_EXTENSIONS);
	for (auto extenName : QString(QTextFile(EXTEN_SAVE_FILE, QIODevice::ReadOnly).readAll()).split(">")) Load(extenName);
	Sync();
}

ExtenWindow::~ExtenWindow()
{
	delete ui;
}

void ExtenWindow::Add(QFileInfo extenFile)
{
	if (extenFile.suffix() == "dll")
	{
		if (extenFile.absolutePath() != QDir::currentPath())
		{
			if (QFile::exists(extenFile.fileName()) && QMessageBox::question(this, EXTENSIONS, CONFIRM_EXTENSION_OVERWRITE) == QMessageBox::Yes) QFile::remove(extenFile.fileName());
			if (!QFile::copy(extenFile.absoluteFilePath(), extenFile.fileName())) QMessageBox::warning(this, EXTENSIONS, EXTENSION_WRITE_ERROR);
		}
		if (Load(extenFile.completeBaseName())) return Sync();
	}
	QMessageBox::information(this, EXTENSIONS, QString(INVALID_EXTENSION).arg(extenFile.fileName()));
}

void ExtenWindow::Sync()
{
	ui->extenList->clear();
	QTextFile extenSaveFile(EXTEN_SAVE_FILE, QIODevice::WriteOnly | QIODevice::Truncate);
	concurrency::reader_writer_lock::scoped_lock_read readLock(extenMutex);
	for (auto extension : extensions)
	{
		ui->extenList->addItem(S(extension.name));
		extenSaveFile.write((S(extension.name) + ">").toUtf8());
	}
}

bool ExtenWindow::eventFilter(QObject* target, QEvent* event)
{
	// See https://stackoverflow.com/questions/1224432/how-do-i-respond-to-an-internal-drag-and-drop-operation-using-a-qlistwidget/1528215
	if (event->type() == QEvent::ChildRemoved)
	{
		QStringList extenNames;
		for (int i = 0; i < ui->extenList->count(); ++i) extenNames.push_back(ui->extenList->item(i)->text());
		Reorder(extenNames);
		Sync();
	}
	return false;
}

void ExtenWindow::keyPressEvent(QKeyEvent* event)
{
	if (event->key() == Qt::Key_Delete && ui->extenList->currentItem())
	{
		Unload(ui->extenList->currentIndex().row());
		Sync();
	}
}

void ExtenWindow::dragEnterEvent(QDragEnterEvent* event)
{
	event->acceptProposedAction();
}

void ExtenWindow::dropEvent(QDropEvent* event)
{
	for (auto file : event->mimeData()->urls()) Add(file.toLocalFile());
}

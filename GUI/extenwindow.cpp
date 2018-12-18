#include "extenwindow.h"
#include "ui_extenwindow.h"
#include "defs.h"
#include "text.h"
#include "types.h"
#include "misc.h"
#include <shared_mutex>
#include <QFileDialog>
#include <QMimeData>
#include <QUrl>

namespace
{
	struct InfoForExtension
	{
		const char* name;
		int64_t value;
		InfoForExtension* next;
		~InfoForExtension() { if (next) delete next; };
	};

	QHash<QString, wchar_t*(*)(const wchar_t*, const InfoForExtension*)> extensions;
	QStringList extenNames;
	std::shared_mutex extenMutex;

	void Load(QString extenName)
	{
		if (extenName == ITH_DLL) return;
		// Extension is dll and exports "OnNewSentence"
		HMODULE module = GetModuleHandleW(S(extenName).c_str());
		if (!module) module = LoadLibraryW(S(extenName).c_str());
		if (!module) return;
		FARPROC callback = GetProcAddress(module, "OnNewSentence");
		if (!callback) return;
		LOCK(extenMutex);
		extensions[extenName] = (wchar_t*(*)(const wchar_t*, const InfoForExtension*))callback;
		extenNames.push_back(extenName);
	}

	void Unload(QString extenName)
	{
		LOCK(extenMutex);
		extenNames.erase(std::remove(extenNames.begin(), extenNames.end(), extenName), extenNames.end());
		FreeLibrary(GetModuleHandleW(S(extenName).c_str()));
	}

	void Reorder(QStringList extenNames)
	{
		LOCK(extenMutex);
		::extenNames = extenNames;
	}
}

bool DispatchSentenceToExtensions(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo)
{
	bool success = true;
	wchar_t* sentenceBuffer = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (sentence.size() + 1) * sizeof(wchar_t));
	wcscpy_s(sentenceBuffer, sentence.size() + 1, sentence.c_str());

	InfoForExtension miscInfoLinkedList{ "", 0, nullptr };
	InfoForExtension* miscInfoTraverser = &miscInfoLinkedList;
	for (auto& i : miscInfo) miscInfoTraverser = miscInfoTraverser->next = new InfoForExtension{ i.first.c_str(), i.second, nullptr };

	std::shared_lock sharedLock(extenMutex);
	for (auto extenName : extenNames)
	{
		wchar_t* nextBuffer = extensions[extenName](sentenceBuffer, &miscInfoLinkedList);
		if (nextBuffer == nullptr) { success = false; break; }
		if (nextBuffer != sentenceBuffer) HeapFree(GetProcessHeap(), 0, sentenceBuffer);
		sentenceBuffer = nextBuffer;
	}
	sentence = sentenceBuffer;

	HeapFree(GetProcessHeap(), 0, sentenceBuffer);
	return success;
}

ExtenWindow::ExtenWindow(QWidget* parent) :
	QMainWindow(parent),
	ui(new Ui::ExtenWindow)
{
	ui->setupUi(this);

	ui->extenList->installEventFilter(this);

	connect(ui->addButton, &QPushButton::clicked, [this] { Add(QFileDialog::getOpenFileName(this, SELECT_EXTENSION, "C:\\", EXTENSION_FILES)); });
	connect(ui->rmvButton, &QPushButton::clicked, [this] { if (auto extenName = ui->extenList->currentItem()) Unload(extenName->text()); Sync(); });

	for (auto extenName : QString(QAutoFile(EXTEN_SAVE_FILE, QIODevice::ReadOnly)->readAll()).split(">")) Load(extenName);
	Sync();
}

ExtenWindow::~ExtenWindow()
{
	delete ui;
}

void ExtenWindow::Sync()
{
	ui->extenList->clear();
	QAutoFile extenSaveFile(EXTEN_SAVE_FILE, QIODevice::WriteOnly | QIODevice::Truncate);
	std::shared_lock sharedLock(extenMutex);
	for (auto extenName : extenNames)
	{
		ui->extenList->addItem(extenName);
		extenSaveFile->write((extenName + ">").toUtf8());
	}
}

void ExtenWindow::Add(QFileInfo extenFile)
{
	if (extenFile.suffix() != "dll") return;
	QFile::copy(extenFile.fileName(), extenFile.absoluteFilePath());
	Load(extenFile.completeBaseName());
	Sync();
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

void ExtenWindow::dragEnterEvent(QDragEnterEvent* event)
{
	event->acceptProposedAction();
}

void ExtenWindow::dropEvent(QDropEvent* event) 
{ 
	for (auto file : event->mimeData()->urls()) Add(file.toLocalFile());
}

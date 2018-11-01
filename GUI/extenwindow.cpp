#include "extenwindow.h"
#include "ui_extenwindow.h"
#include "types.h"
#include <QFileDialog>

namespace
{
	struct InfoForExtension
	{
		const char* name;
		int64_t value;
		InfoForExtension* next;
		~InfoForExtension() { if (next) delete next; };
	};

	struct Extension
	{
		QString name;
		wchar_t*(*callback)(const wchar_t*, const InfoForExtension*);
	};

	std::shared_mutex extenMutex;
	QVector<Extension> extensions;

	void Load(QString extenName)
	{
		// Extension is dll and exports "OnNewSentence"
		HMODULE module = GetModuleHandleW(extenName.toStdWString().c_str());
		if (!module) module = LoadLibraryW(extenName.toStdWString().c_str());
		if (!module) return;
		FARPROC callback = GetProcAddress(module, "OnNewSentence");
		if (!callback) return;
		extensions.push_back({ extenName, (wchar_t*(*)(const wchar_t*, const InfoForExtension*))callback });
	}

	void Unload(QString extenName)
	{
		extensions.erase(std::remove_if(extensions.begin(), extensions.end(), [&](Extension extension) { return extension.name == extenName; }), extensions.end());
		FreeLibrary(GetModuleHandleW(extenName.toStdWString().c_str()));
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
	for (auto extension : extensions)
	{
		wchar_t* nextBuffer = extension.callback(sentenceBuffer, &miscInfoLinkedList);
		if (nextBuffer == nullptr) { success = false; break; }
		if (nextBuffer != sentenceBuffer) HeapFree(GetProcessHeap(), 0, sentenceBuffer);
		sentenceBuffer = nextBuffer;
	}
	sentence = std::wstring(sentenceBuffer);

	HeapFree(GetProcessHeap(), 0, sentenceBuffer);
	return success;
}

ExtenWindow::ExtenWindow(QWidget* parent) :
	QMainWindow(parent),
	ui(new Ui::ExtenWindow)
{
	ui->setupUi(this);

	extenList = findChild<QListWidget*>("extenList");
	extenList->installEventFilter(this);

	if (extensions.empty())
	{
		extenSaveFile.open(QIODevice::ReadOnly);
		for (auto extenName : QString(extenSaveFile.readAll()).split(">")) Load(extenName);
		extenSaveFile.close();
	}
	Sync();
}

ExtenWindow::~ExtenWindow()
{
	delete ui;
}

void ExtenWindow::on_addButton_clicked()
{
	QString extenFileName = QFileDialog::getOpenFileName(this, "Select Extension", "C:\\", "Extensions (*.dll)");
	if (!extenFileName.size()) return;
	QString extenName = extenFileName.mid(extenFileName.lastIndexOf("/") + 1);
	QFile::copy(extenFileName, extenName);
	Load(extenName.left(extenName.lastIndexOf(".dll")));
	Sync();
}

void ExtenWindow::on_rmvButton_clicked()
{
	if (auto extenName = extenList->currentItem()) Unload(extenName->text());
	Sync();
}

bool ExtenWindow::eventFilter(QObject* target, QEvent* event) 
{ 
	// See https://stackoverflow.com/questions/1224432/how-do-i-respond-to-an-internal-drag-and-drop-operation-using-a-qlistwidget/1528215
	if (event->type() == QEvent::ChildRemoved)
	{
		QVector<Extension> newExtensions;
		for (int i = 0; i < extenList->count(); ++i)
			newExtensions.push_back(*std::find_if(extensions.begin(), extensions.end(), [=](Extension extension) { return extension.name == extenList->item(i)->text(); }));
		extensions = newExtensions;
		Sync();
	}
	return false; 
}

void ExtenWindow::Sync()
{
	extenList->clear();
	extenSaveFile.open(QIODevice::WriteOnly | QIODevice::Truncate);
	for (auto extension : extensions)
	{
		extenList->addItem(extension.name);
		extenSaveFile.write((extension.name + ">").toUtf8());
	}
	extenSaveFile.close();
}

#include "extendialog.h"
#include "ui_extendialog.h"
#include "types.h"
#include <QFileDialog>

ListRearrangeFilter::ListRearrangeFilter(QWidget* parent) : QObject(parent) {}

bool ListRearrangeFilter::eventFilter(QObject*, QEvent* event)
{
	if (event->type() == QEvent::ChildRemoved) emit SigRearranged();
	return false;
}

ExtenDialog::ExtenDialog(QWidget* parent) :
	QDialog(parent),
	ui(new Ui::ExtenDialog),
	filter(new ListRearrangeFilter(this))
{
	ui->setupUi(this);

	extenList = findChild<QListWidget*>("extenList");
	extenList->installEventFilter(filter);
	connect(filter, &ListRearrangeFilter::SigRearranged, this, &ExtenDialog::Rearrange);

	if (extensions.empty())
	{
		extenSaveFile.open(QIODevice::ReadOnly);
		for (auto extenName : QString(extenSaveFile.readAll()).split(">")) Load(extenName);
		extenSaveFile.close();
	}

	for (auto extension : extensions)
		extenList->addItem(extension.name);
}

ExtenDialog::~ExtenDialog()
{
	delete ui;
}

bool ExtenDialog::DispatchSentenceToExtensions(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo)
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

void ExtenDialog::Load(QString extenName)
{
	// Extension is dll and exports "OnNewSentence"
	HMODULE module = GetModuleHandleW(extenName.toStdWString().c_str());
	if (!module) module = LoadLibraryW(extenName.toStdWString().c_str());
	if (!module) return;
	FARPROC callback = GetProcAddress(module, "OnNewSentence");
	if (!callback) return;
	extensions.push_back({ extenName, (wchar_t*(*)(const wchar_t*, const InfoForExtension*))callback });
}

void ExtenDialog::Unload(QString extenName)
{
	extensions.erase(std::remove_if(extensions.begin(), extensions.end(), [&](Extension extension) { return extension.name == extenName; }), extensions.end());
	FreeLibrary(GetModuleHandleW(extenName.toStdWString().c_str()));
}

void ExtenDialog::on_addButton_clicked()
{
	QString extenFileName = QFileDialog::getOpenFileName(this, "Select Extension", "C:\\", "Extensions (*.dll)");
	if (!extenFileName.size()) return;
	QString extenName = extenFileName.mid(extenFileName.lastIndexOf("/") + 1);
	QFile::copy(extenFileName, extenName);
	Load(extenName.left(extenName.lastIndexOf(".dll")));
	Sync();
}

void ExtenDialog::on_rmvButton_clicked()
{
	for (auto extenName : extenList->selectedItems()) Unload(extenName->text());
	Sync();
}

void ExtenDialog::Rearrange()
{
	QVector<Extension> newExtensions;
	for (int i = 0; i < extenList->count(); ++i)
		newExtensions.push_back(*std::find_if(extensions.begin(), extensions.end(), [=](Extension extension) { return extension.name == extenList->item(i)->text(); }));
	extensions = newExtensions;
	Sync();
}

void ExtenDialog::Sync()
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

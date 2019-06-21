#include "extension.h"
#include <QMainWindow>
#include <QLayout>
#include <QPushButton>
#include <QListWidget>
#include <QInputDialog>
#include <QKeyEvent>

extern const char* THREAD_LINKER;
extern const char* LINK;
extern const char* THREAD_LINK_FROM;
extern const char* THREAD_LINK_TO;
extern const char* HEXADECIMAL;

std::unordered_map<int64_t, std::unordered_multiset<int64_t>> linkedTextHandles;
std::shared_mutex m;

class Window : public QMainWindow
{
public:
	Window()
	{
		connect(&linkButton, &QPushButton::clicked, this, &Window::Link);

		layout.addWidget(&linkList);
		layout.addWidget(&linkButton);

		setCentralWidget(&centralWidget);
		setWindowTitle(THREAD_LINKER);
		QMetaObject::invokeMethod(this, &QWidget::show, Qt::QueuedConnection);
	}

private:
	void Link()
	{
		bool ok1, ok2, ok3, ok4;
		int from = QInputDialog::getText(this, THREAD_LINK_FROM, HEXADECIMAL, QLineEdit::Normal, "", &ok1, Qt::WindowCloseButtonHint).toInt(&ok2, 16);
		int to = QInputDialog::getText(this, THREAD_LINK_TO, HEXADECIMAL, QLineEdit::Normal, "", &ok3, Qt::WindowCloseButtonHint).toInt(&ok4, 16);
		if (ok1 && ok2 && ok3 && ok4)
		{
			std::lock_guard l(m);
			linkedTextHandles[from].insert(to);
			linkList.addItem(QString::number(from, 16) + "->" + QString::number(to, 16));
		}
	}

	void keyPressEvent(QKeyEvent* event) override
	{
		if (event->key() == Qt::Key_Delete && linkList.currentItem())
		{
			QStringList link = linkList.currentItem()->text().split("->");
			linkList.takeItem(linkList.currentRow());
			std::lock_guard l(m);
			linkedTextHandles[link[0].toInt(nullptr, 16)].erase(link[1].toInt(nullptr, 16));
		}
	}

	QWidget centralWidget{ this };
	QHBoxLayout layout{ &centralWidget };
	QListWidget linkList{ &centralWidget };
	QPushButton linkButton{ LINK, &centralWidget };
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	std::shared_lock l(m);
	int64_t textHandle = sentenceInfo["text number"];

	for (auto linkedHandle : linkedTextHandles[textHandle])
		((void(*)(void*, int64_t, const wchar_t*))sentenceInfo["void (*AddSentence)(void* this, int64_t number, const wchar_t* sentence)"])
			((void*)sentenceInfo["this"], linkedHandle, sentence.c_str());

	return false;
}

#include "qtcommon.h"
#include "extension.h"
#include <QKeyEvent>

extern const char* THREAD_LINKER;
extern const char* LINK;
extern const char* UNLINK;
extern const char* THREAD_LINK_FROM;
extern const char* THREAD_LINK_TO;
extern const char* HEXADECIMAL;

std::unordered_map<int64_t, std::unordered_set<int64_t>> linkedTextHandles;
concurrency::reader_writer_lock m;

class Window : public QDialog, Localizer
{
public:
	Window() : QDialog(nullptr, Qt::WindowMinMaxButtonsHint)
	{
		connect(&linkButton, &QPushButton::clicked, this, &Window::Link);
		connect(&unlinkButton, &QPushButton::clicked, this, &Window::Unlink);

		layout.addWidget(&linkList);
		layout.addLayout(&buttons);
		buttons.addSpacerItem(new QSpacerItem(0, 0, QSizePolicy::Minimum, QSizePolicy::Expanding));
		buttons.addWidget(&linkButton);
		buttons.addWidget(&unlinkButton);
		buttons.addSpacerItem(new QSpacerItem(0, 0, QSizePolicy::Minimum, QSizePolicy::Expanding));

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
			std::scoped_lock lock(m);
			if (linkedTextHandles[from].insert(to).second) linkList.addItem(QString::number(from, 16) + "->" + QString::number(to, 16));
		}
	}

	void Unlink()
	{
		if (linkList.currentItem())
		{
			QStringList link = linkList.currentItem()->text().split("->");
			linkList.takeItem(linkList.currentRow());
			std::scoped_lock lock(m);
			linkedTextHandles[link[0].toInt(nullptr, 16)].erase(link[1].toInt(nullptr, 16));
		}
	}

	void keyPressEvent(QKeyEvent* event) override
	{
		if (event->key() == Qt::Key_Delete) Unlink();
	}

	QHBoxLayout layout{ this };
	QVBoxLayout buttons;
	QListWidget linkList{ this };
	QPushButton linkButton{ LINK, this }, unlinkButton{ UNLINK, this };
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	concurrency::reader_writer_lock::scoped_lock_read readLock(m);
	auto links = linkedTextHandles.find(sentenceInfo["text number"]);
	if (links != linkedTextHandles.end()) for (auto link : links->second)
		((void(*)(int64_t, const wchar_t*))sentenceInfo["void (*AddText)(int64_t number, const wchar_t* text)"])(link, sentence.c_str());
	return false;
}

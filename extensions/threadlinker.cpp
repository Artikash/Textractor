#include "qtcommon.h"
#include "extension.h"
#include <QKeyEvent>

extern const char* THREAD_LINKER;
extern const char* LINK;
extern const char* THREAD_LINK_FROM;
extern const char* THREAD_LINK_TO;
extern const char* HEXADECIMAL;

std::unordered_map<int64_t, std::unordered_multiset<int64_t>> linkedTextHandles;
std::shared_mutex m;

class Window : public QDialog, Localizer
{
public:
	Window() : QDialog(nullptr, Qt::WindowMinMaxButtonsHint)
	{
		connect(&linkButton, &QPushButton::clicked, this, &Window::Link);

		layout.addWidget(&linkList);
		layout.addWidget(&linkButton);

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
			std::scoped_lock lock(m);
			linkedTextHandles[link[0].toInt(nullptr, 16)].erase(link[1].toInt(nullptr, 16));
		}
	}

	QHBoxLayout layout{ this };
	QListWidget linkList{ this };
	QPushButton linkButton{ LINK, this };
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	std::shared_lock lock(m);
	int64_t textHandle = sentenceInfo["text number"];

	for (auto linkedHandle : linkedTextHandles[textHandle])
		((void(*)(int64_t, const wchar_t*))sentenceInfo["void (*AddText)(int64_t number, const wchar_t* text)"])(linkedHandle, sentence.c_str());

	return false;
}

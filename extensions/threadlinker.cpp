#include "extension.h"
#include "text.h"
#include <QMainWindow>
#include <QLayout>
#include <QPushButton>
#include <QListWidget>
#include <QInputDialog>
#include <QKeyEvent>
#include <QTimer>

std::mutex m;
std::unordered_map<int64_t, std::unordered_multiset<int64_t>> linkedTextHandles;

struct : QMainWindow
{
	void launch()
	{
		auto centralWidget = new QWidget(this);
		auto layout = new QHBoxLayout(centralWidget);
		auto linkList = new QListWidget(centralWidget);
		auto addLink = new QPushButton(LINK, centralWidget);
		layout->addWidget(linkList);
		layout->addWidget(addLink);

		connect(addLink, &QPushButton::clicked, [=]
		{
			bool ok1, ok2, ok3, ok4;
			int from = QInputDialog::getText(this, THREAD_LINK_FROM, "", QLineEdit::Normal, "0x", &ok1, Qt::WindowCloseButtonHint).toInt(&ok2, 16);
			int to = QInputDialog::getText(this, THREAD_LINK_TO, "", QLineEdit::Normal, "0x", &ok3, Qt::WindowCloseButtonHint).toInt(&ok4, 16);
			if (ok1 && ok2 && ok3 && ok4)
			{
				std::lock_guard l(m);
				linkedTextHandles[from].insert(to);
				linkList->addItem(QString::number(from, 16) + "->" + QString::number(to, 16));
			}
		});
		Unlink = [=]
		{
			if (linkList->currentItem())
			{
				QStringList link = linkList->currentItem()->text().split("->");
				linkList->takeItem(linkList->currentRow());
				std::lock_guard l(m);
				linkedTextHandles[link[0].toInt(nullptr, 16)].erase(link[1].toInt(nullptr, 16));
			}
		};

		setCentralWidget(centralWidget);
		setWindowTitle(THREAD_LINKER);
		show();
	}

	void keyPressEvent(QKeyEvent* event) override
	{
		if (event->key() == Qt::Key_Delete) Unlink();
	}

	std::function<void()> Unlink;
}*window = nullptr;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		QTimer::singleShot(0, []
		{
			std::lock_guard l(m);
			(window = new std::remove_pointer_t<decltype(window)>)->launch();
		});
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		if (lpReserved == NULL) // https://blogs.msdn.microsoft.com/oldnewthing/20120105-00/?p=8683
		{
			std::lock_guard l(m);
			delete window;
			window = nullptr;
		}
	}
	break;
	}
	return TRUE;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	std::lock_guard l(m);
	static std::unordered_map<int64_t, std::wstring> queuedWritesByHandle;
	int64_t textHandle = sentenceInfo["text handle"];

	for (auto linkedHandle : linkedTextHandles[textHandle]) queuedWritesByHandle[linkedHandle] += L"\n" + sentence;

	if (queuedWritesByHandle[textHandle].empty()) return false;
	sentence += queuedWritesByHandle[textHandle];
	queuedWritesByHandle[textHandle].clear();
	return true;
}

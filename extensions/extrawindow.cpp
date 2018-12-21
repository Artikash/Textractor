#include "extension.h"
#include "text.h"
#include <QMainWindow>
#include <QLayout>
#include <QLabel>
#include <QCheckBox>
#include <QTimer>

std::mutex m;

struct : QMainWindow 
{
	QLabel* display;
	void launch()
	{
		auto centralWidget = new QWidget(this);
		auto layout = new QVBoxLayout(centralWidget);
		auto options = new QHBoxLayout(centralWidget);
		layout->addItem(options);
		layout->addWidget(display = new QLabel(centralWidget));
		auto onTop = new QCheckBox(ALWAYS_ON_TOP, this);
		options->addWidget(onTop);
		connect(onTop, &QCheckBox::stateChanged, [this](int state) 
		{ 
			SetWindowPos((HWND)winId(), state == Qt::Checked ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE); 
		});
		resize(800, 600);
		setCentralWidget(centralWidget);
		show();
	}
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
	if (window == nullptr || !sentenceInfo["current select"]) return false;
	window->display->setText(QString::fromStdWString(sentence));
	return false;
}

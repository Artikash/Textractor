#include "extension.h"
#include <QMainWindow>
#include <QLayout>
#include <QLabel>
#include <QLineEdit>
#include <QTimer>

std::wregex regex;
std::mutex m;

struct : QMainWindow {
	void Initialize()
	{
		auto centralWidget = new QWidget(this);
		auto layout = new QVBoxLayout(centralWidget);
		auto input = new QLineEdit(centralWidget);
		auto output = new QLabel(centralWidget);
		output->setAlignment(Qt::AlignCenter);
		layout->addWidget(input);
		layout->addWidget(output);
		connect(input, &QLineEdit::textEdited, [=](QString newRegex) 
		{
			std::lock_guard l(m);
			try { regex = newRegex.toStdWString(); }
			catch (...) { return output->setText("Invalid regex"); }
			output->setText("Currently filtering: " + newRegex);
		});
		QMainWindow::resize(350, 60);
		QMainWindow::setCentralWidget(centralWidget);
		QMainWindow::setWindowTitle("Regex Filter");
		QMainWindow::show();
	}
}*window = nullptr;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	std::lock_guard l(m);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		QTimer::singleShot(0, [] { (window = new std::remove_pointer_t<decltype(window)>)->Initialize(); });
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		if (lpReserved == NULL) // https://blogs.msdn.microsoft.com/oldnewthing/20120105-00/?p=8683
		{
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
	if (window == nullptr || sentenceInfo["hook address"] == -1) return false;
	sentence = std::regex_replace(sentence, regex, L"");
	return true;
}

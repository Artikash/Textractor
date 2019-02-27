#include "extension.h"
#include <QMainWindow>
#include <QLayout>
#include <QLabel>
#include <QLineEdit>
#include <QTimer>

extern const char* REGEX_FILTER;
extern const char* INVALID_REGEX;
extern const char* CURRENT_FILTER;

std::wregex regex;
std::shared_mutex m;

struct : QMainWindow 
{
	void launch()
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
			catch (...) { return output->setText(INVALID_REGEX); }
			output->setText(CURRENT_FILTER + newRegex);
		});
		resize(350, 60);
		setCentralWidget(centralWidget);
		setWindowTitle(REGEX_FILTER);
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
	std::shared_lock l(m);
	if (sentenceInfo["text number"] == 0) return false;
	sentence = std::regex_replace(sentence, regex, L"");
	return true;
}

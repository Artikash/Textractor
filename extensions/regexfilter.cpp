#include "qtcommon.h"
#include "extension.h"
#include "ui_regexfilter.h"

extern const char* REGEX_FILTER;
extern const char* INVALID_REGEX;
extern const char* CURRENT_FILTER;

std::wregex regex;
std::shared_mutex m;

class Window : public QMainWindow 
{
public:
	Window()
	{
		ui.setupUi(this);

		connect(ui.input, &QLineEdit::textEdited, this, &Window::setRegex);
		
		setWindowTitle(REGEX_FILTER);
		QMetaObject::invokeMethod(this, &QWidget::show, Qt::QueuedConnection);
	}

private:
	void setRegex(QString regex)
	{
		std::lock_guard l(m);
		try { ::regex = S(regex); }
		catch (std::regex_error) { return ui.output->setText(INVALID_REGEX); }
		ui.output->setText(QString(CURRENT_FILTER).arg(regex));
	}

	Ui::FilterWindow ui;
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0) return false;
	std::shared_lock l(m);
	sentence = std::regex_replace(sentence, regex, L"");
	return true;
}

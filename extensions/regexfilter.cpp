#include "qtcommon.h"
#include "extension.h"
#include "ui_regexfilter.h"
#include "module.h"
#include "blockmarkup.h"
#include <fstream>

extern const char* REGEX_FILTER;
extern const char* INVALID_REGEX;
extern const char* CURRENT_FILTER;

const char* REGEX_SAVE_FILE = "SavedRegexFilters.txt";

std::optional<std::wregex> regex;
std::shared_mutex m;
DWORD (*GetSelectedProcessId)() = nullptr;

class Window : public QDialog
{
public:
	Window()
		: QDialog(nullptr, Qt::WindowMinMaxButtonsHint)
	{
		ui.setupUi(this);

		connect(ui.input, &QLineEdit::textEdited, this, &Window::setRegex);
		connect(ui.save, &QPushButton::clicked, this, &Window::saveRegex);
		
		setWindowTitle(REGEX_FILTER);
		QMetaObject::invokeMethod(this, &QWidget::show, Qt::QueuedConnection);
	}

	void setRegex(QString regex)
	{
		ui.input->setText(regex);
		std::lock_guard l(m);
		if (!regex.isEmpty()) try { ::regex = S(regex); }
		catch (std::regex_error) { return ui.output->setText(INVALID_REGEX); }
		else ::regex = std::nullopt;
		ui.output->setText(QString(CURRENT_FILTER).arg(regex));
	}

private:
	void saveRegex()
	{
		auto formatted = FormatString(
			L"\xfeff|PROCESS|%s|FILTER|%s|END|\r\n",
			GetModuleFilename(GetSelectedProcessId()).value_or(FormatString(L"Error getting name of process 0x%X", GetSelectedProcessId())),
			S(ui.input->text())
		);
		std::ofstream(REGEX_SAVE_FILE, std::ios::binary | std::ios::app).write((const char*)formatted.c_str(), formatted.size() * sizeof(wchar_t));
	}

	Ui::FilterWindow ui;
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	static auto _ = GetSelectedProcessId = (DWORD(*)())sentenceInfo["DWORD (*GetSelectedProcessId)()"];
	if (sentenceInfo["text number"] == 0) return false;
	if (sentenceInfo["current select"] && !regex) if (auto processName = GetModuleFilename(sentenceInfo["process id"]))
	{
		std::ifstream stream(REGEX_SAVE_FILE, std::ios::binary);
		BlockMarkupIterator savedFilters(stream, Array<std::wstring_view>{ L"|PROCESS|", L"|FILTER|" });
		std::vector<std::wstring> regexes;
		while (auto read = savedFilters.Next()) if (read->at(0) == processName) regexes.push_back(std::move(read->at(1)));
		if (!regexes.empty()) QMetaObject::invokeMethod(&window, [regex = S(regexes.back())] { window.setRegex(regex); }, Qt::BlockingQueuedConnection);
	}
	std::shared_lock l(m);
	if (regex) sentence = std::regex_replace(sentence, regex.value(), L"");
	return true;
}

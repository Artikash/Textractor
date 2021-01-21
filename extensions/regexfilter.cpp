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
std::wstring replace;
std::shared_mutex m;
DWORD (*GetSelectedProcessId)() = nullptr;

class Window : public QDialog, Localizer
{
public:
	Window()
		: QDialog(nullptr, Qt::WindowMinMaxButtonsHint)
	{
		ui.setupUi(this);

		connect(ui.regexEdit, &QLineEdit::textEdited, this, &Window::SetRegex);
		connect(ui.replaceEdit, &QLineEdit::textEdited, this, &Window::SetReplace);
		connect(ui.saveButton, &QPushButton::clicked, this, &Window::Save);
		
		setWindowTitle(REGEX_FILTER);
		QMetaObject::invokeMethod(this, &QWidget::show, Qt::QueuedConnection);
	}

	void SetRegex(QString regex)
	{
		ui.regexEdit->setText(regex);
		std::scoped_lock lock(m);
		if (!regex.isEmpty()) try { ::regex = S(regex); }
		catch (std::regex_error) { return ui.output->setText(INVALID_REGEX); }
		else ::regex = std::nullopt;
		ui.output->setText(QString(CURRENT_FILTER).arg(regex));
	}

	void SetReplace(QString replace)
	{
		ui.replaceEdit->setText(replace);
		std::scoped_lock lock(m);
		::replace = S(replace);
	}

private:
	void Save()
	{
		auto formatted = FormatString(
			L"\xfeff|PROCESS|%s|FILTER|%s|REPLACE|%s|END|\r\n",
			GetModuleFilename(GetSelectedProcessId()).value_or(FormatString(L"Error getting name of process 0x%X", GetSelectedProcessId())),
			S(ui.regexEdit->text()),
			S(ui.replaceEdit->text())
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
		BlockMarkupIterator savedFilters(stream, Array<std::wstring_view>{ L"|PROCESS|", L"|FILTER|", L"|REPLACE|" });
		std::vector<std::array<std::wstring, 3>> regexes;
		while (auto read = savedFilters.Next()) if (read->at(0) == processName) regexes.push_back(std::move(read.value()));
		if (!regexes.empty()) QMetaObject::invokeMethod(&window, [regex = S(regexes.back()[1]), replace = S(regexes.back()[2])]
		{
			window.SetRegex(regex);
			window.SetReplace(replace);
		}, Qt::BlockingQueuedConnection);
	}
	std::shared_lock l(m);
	if (regex) sentence = std::regex_replace(sentence, regex.value(), replace);
	return true;
}

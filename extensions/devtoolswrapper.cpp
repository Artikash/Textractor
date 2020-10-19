#include "qtcommon.h"
#include "extension.h"
#include "blockmarkup.h"
#include "network.h"
#include <map>
#include <fstream>
#include <QComboBox>
#include "devtools.h"

extern const char* NATIVE_LANGUAGE;
extern const char* TRANSLATE_TO;
extern const char* TRANSLATE_SELECTED_THREAD_ONLY;
extern const char* USE_TRANS_CACHE;
extern const char* MAX_SENTENCE_SIZE;
extern const char* TRANSLATION_PROVIDER;
extern QStringList languages;
const char* PATH_TO_CHROME = u8"Path to chrome";
const char* AUTO_START_CHROME = u8"Start chrome automatically";
const char* HEADLESS_CHROME = u8"Start in headless mode";
const char* CHROME_DEBUG_PORT = u8"Chrome debug port";
const char* DEV_TOOLS_STATUS = u8"Status: ";
const char* START_DEV_TOOLS_BUTTON = u8"Start";
const char* START_DEV_TOOLS = u8"Start chrome";
const char* STOP_DEV_TOOLS_BUTTON = u8"Stop";
const char* STOP_DEV_TOOLS = u8"Stop chrome";

extern bool useCache, autostartchrome, headlesschrome;
extern int maxSentenceSize, chromeport;

std::pair<bool, std::wstring> Translate(const std::wstring& text, DevTools* devtools);

const char* LANGUAGE = u8"Language";
const std::string TRANSLATION_CACHE_FILE = FormatString("%s Cache.txt", TRANSLATION_PROVIDER);

QFormLayout* display;
QSettings settings = openSettings();
Synchronized<std::wstring> translateTo = L"en";
Synchronized<std::map<std::wstring, std::wstring>> translationCache;

int savedSize;
DevTools* devtools = nullptr;
std::wstring pathtochrome = L"";

void SaveCache()
{
	std::wstring allTranslations(L"\xfeff");
	for (const auto& [sentence, translation] : translationCache.Acquire().contents)
		allTranslations.append(L"|SENTENCE|").append(sentence).append(L"|TRANSLATION|").append(translation).append(L"|END|\r\n");
	std::ofstream(TRANSLATION_CACHE_FILE, std::ios::binary | std::ios::trunc).write((const char*)allTranslations.c_str(), allTranslations.size() * sizeof(wchar_t));
	savedSize = translationCache->size();
}

void EraseControlCharacters(std::wstring& text)
{
	for (auto it = text.begin(); it!= text.end(); ++it)
	{
		if ((*it == '\n') || (*it == '\r') || (*it == '\t') || (int(*it) == 4) || (int(*it) == 5))
		{
			text.erase(it--);
		}
	}
}

class Window : public QDialog
{
public:
	Window() :
		QDialog(nullptr, Qt::WindowMinMaxButtonsHint)
	{
		display = new QFormLayout(this);
		settings.beginGroup(TRANSLATION_PROVIDER);

		auto languageBox = new QComboBox(this);
		languageBox->addItems(languages);
		int language = -1;
		if (settings.contains(LANGUAGE)) language = languageBox->findText(settings.value(LANGUAGE).toString(), Qt::MatchEndsWith);
		if (language < 0) language = languageBox->findText(NATIVE_LANGUAGE, Qt::MatchStartsWith);
		if (language < 0) language = languageBox->findText("English", Qt::MatchStartsWith);
		languageBox->setCurrentIndex(language);
		saveLanguage(languageBox->currentText());
		display->addRow(TRANSLATE_TO, languageBox);
		connect(languageBox, &QComboBox::currentTextChanged, this, &Window::saveLanguage);
		for (auto [value, label] : Array<bool&, const char*>{
			{ useCache, USE_TRANS_CACHE },
			{ autostartchrome, AUTO_START_CHROME },
			//{ headlesschrome, HEADLESS_CHROME }
			})
		{
			value = settings.value(label, value).toBool();
			auto checkBox = new QCheckBox(this);
			checkBox->setChecked(value);
			display->addRow(label, checkBox);
			connect(checkBox, &QCheckBox::clicked, [label, &value](bool checked) { settings.setValue(label, value = checked); });
		}
		for (auto [value, label] : Array<int&, const char*>{
			{ maxSentenceSize, MAX_SENTENCE_SIZE },
			{ chromeport, CHROME_DEBUG_PORT },
			})
		{
			value = settings.value(label, value).toInt();
			auto spinBox = new QSpinBox(this);
			spinBox->setRange(0, INT_MAX);
			spinBox->setValue(value);
			display->addRow(label, spinBox);
			connect(spinBox, qOverload<int>(&QSpinBox::valueChanged), [label, &value](int newValue) { settings.setValue(label, value = newValue); });
		}

		auto keyInput = new QLineEdit(settings.value(PATH_TO_CHROME).toString());
		pathtochrome = (S(keyInput->text()));
		if (pathtochrome.empty())
		{
			for (auto defaultpath : Array<std::wstring>{
				{ L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe" },
				{ L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" },
				})
				if (std::filesystem::exists(defaultpath))
				{
					pathtochrome = defaultpath;
					keyInput->setText(S(pathtochrome));
				}
		}
		connect(keyInput, &QLineEdit::textChanged, [keyInput](QString key) { settings.setValue(PATH_TO_CHROME, S(pathtochrome = (S(key)))); });
		display->addRow(PATH_TO_CHROME, keyInput);

		connect(&startButton, &QPushButton::clicked, this, &Window::start);
		connect(&stopButton, &QPushButton::clicked, this, &Window::stop);
		display->addRow(START_DEV_TOOLS, &startButton);
		display->addRow(STOP_DEV_TOOLS, &stopButton);

		status.setFrameStyle(QFrame::Panel | QFrame::Sunken);
		display->addRow(DEV_TOOLS_STATUS, &status);

		setWindowTitle(TRANSLATION_PROVIDER);
		QMetaObject::invokeMethod(this, &QWidget::show, Qt::QueuedConnection);

		std::ifstream stream(TRANSLATION_CACHE_FILE, std::ios::binary);
		BlockMarkupIterator savedTranslations(stream, Array<std::wstring_view>{ L"|SENTENCE|", L"|TRANSLATION|" });
		auto translationCache = ::translationCache.Acquire();

		while (auto read = savedTranslations.Next())
		{
			auto& [sentence, translation] = read.value();
			translationCache->try_emplace(std::move(sentence), std::move(translation));
		}
		savedSize = translationCache->size();

		devtools = new DevTools(this);
		connect(devtools, &DevTools::statusChanged, [this](QString text)
			{
				status.setText(text);
			});

		if (autostartchrome)
			QMetaObject::invokeMethod(this, &Window::start, Qt::QueuedConnection);
	}

	~Window()
	{
		stop();
		if (devtools != nullptr)
			delete devtools;
		SaveCache();
	}

private:
	void start()
	{
		if (devtools->getStatus() == "Stopped")
			devtools->startDevTools(S(pathtochrome), headlesschrome, chromeport);
	}
	void stop()
	{
		devtools->closeDevTools();
	}


	void saveLanguage(QString language)
	{
		settings.setValue(LANGUAGE, S(translateTo->assign(S(language.split(": ")[1]))));
	}
	QPushButton startButton{ START_DEV_TOOLS_BUTTON, this };
	QPushButton stopButton{ STOP_DEV_TOOLS_BUTTON, this };
	QLabel status{ "Stopped" };
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0 || sentence.size() > maxSentenceSize) return false;

	bool cache = false;
	std::wstring translation;
	if (useCache)
	{
		auto translationCache = ::translationCache.Acquire();
		if (auto it = translationCache->find(sentence); it != translationCache->end()) translation = it->second + L"\x200b";
	}
	if (translation.empty() && (sentenceInfo["current select"]))
	{
		EraseControlCharacters(sentence);
		std::tie(cache, translation) = Translate(sentence, devtools);
	}
		
	if (cache) translationCache->try_emplace(sentence, translation);
	if (cache && translationCache->size() > savedSize + 50) SaveCache();

	JSON::Unescape(translation);
	sentence += L"\n" + translation;
	return true;
}
#include "qtcommon.h"
#include "extension.h"
#include "blockmarkup.h"
#include "network.h"
#include <map>
#include <fstream>
#include <QComboBox>

extern const char* NATIVE_LANGUAGE;
extern const char* TRANSLATE_TO;
extern const char* TRANSLATE_FROM;
extern const char* TRANSLATE_SELECTED_THREAD_ONLY;
extern const char* RATE_LIMIT_ALL_THREADS;
extern const char* RATE_LIMIT_SELECTED_THREAD;
extern const char* USE_TRANS_CACHE;
extern const char* RATE_LIMIT_TOKEN_COUNT;
extern const char* RATE_LIMIT_TOKEN_RESTORE_DELAY;
extern const char* MAX_SENTENCE_SIZE;
extern const char* API_KEY;
extern const wchar_t* TOO_MANY_TRANS_REQUESTS;

extern const char* TRANSLATION_PROVIDER;
extern const char* GET_API_KEY_FROM;
extern QStringList languages;
extern std::wstring autoDetectLanguage;
extern bool translateSelectedOnly, rateLimitAll, rateLimitSelected, useCache;
extern int tokenCount, tokenRestoreDelay, maxSentenceSize;
std::pair<bool, std::wstring> Translate(const std::wstring& text);

// backwards compatibility
const char* LANGUAGE = u8"Language";
const std::string TRANSLATION_CACHE_FILE = FormatString("%s Translation Cache.txt", TRANSLATION_PROVIDER);

QFormLayout* display;
Settings settings;
Synchronized<std::wstring> translateTo = L"en", translateFrom = L"auto", authKey;

namespace
{
	Synchronized<std::map<std::wstring, std::wstring>> translationCache;
	int savedSize;
	void SaveCache()
	{
		std::wstring allTranslations(L"\xfeff");
		for (const auto& [sentence, translation] : translationCache.Acquire().contents)
			allTranslations.append(L"|SENTENCE|").append(sentence).append(L"|TRANSLATION|").append(translation).append(L"|END|\r\n");
		std::ofstream(TRANSLATION_CACHE_FILE, std::ios::binary | std::ios::trunc).write((const char*)allTranslations.c_str(), allTranslations.size() * sizeof(wchar_t));
		savedSize = translationCache->size();
	}
}

class Window : public QDialog, Localizer
{
public:
	Window() : QDialog(nullptr, Qt::WindowMinMaxButtonsHint)
	{
		display = new QFormLayout(this);

		settings.beginGroup(TRANSLATION_PROVIDER);

		auto translateToCombo = new QComboBox(this);
		translateToCombo->addItems(languages);
		int language = -1;
		if (settings.contains(LANGUAGE)) language = translateToCombo->findText(settings.value(LANGUAGE).toString(), Qt::MatchEndsWith);
		if (settings.contains(TRANSLATE_TO)) language = translateToCombo->findText(settings.value(TRANSLATE_TO).toString(), Qt::MatchEndsWith);
		if (language < 0) language = translateToCombo->findText(NATIVE_LANGUAGE, Qt::MatchStartsWith);
		if (language < 0) language = translateToCombo->findText("English", Qt::MatchStartsWith);
		translateToCombo->setCurrentIndex(language);
		SaveTranslateTo(translateToCombo->currentText());
		display->addRow(TRANSLATE_TO, translateToCombo);
		connect(translateToCombo, &QComboBox::currentTextChanged, this, &Window::SaveTranslateTo);
		languages.push_front("?: " + S(autoDetectLanguage));
		auto translateFromCombo = new QComboBox(this);
		translateFromCombo->addItems(languages);
		language = -1;
		if (settings.contains(TRANSLATE_FROM)) language = translateFromCombo->findText(settings.value(TRANSLATE_FROM).toString(), Qt::MatchEndsWith);
		if (language < 0) language = translateFromCombo->findText("?", Qt::MatchStartsWith);
		translateFromCombo->setCurrentIndex(language);
		SaveTranslateFrom(translateFromCombo->currentText());
		display->addRow(TRANSLATE_FROM, translateFromCombo);
		connect(translateFromCombo, &QComboBox::currentTextChanged, this, &Window::SaveTranslateFrom);
		for (auto [value, label] : Array<bool&, const char*>{
			{ translateSelectedOnly, TRANSLATE_SELECTED_THREAD_ONLY },
			{ rateLimitAll, RATE_LIMIT_ALL_THREADS },
			{ rateLimitSelected, RATE_LIMIT_SELECTED_THREAD },
			{ useCache, USE_TRANS_CACHE },
		})
		{
			value = settings.value(label, value).toBool();
			auto checkBox = new QCheckBox(this);
			checkBox->setChecked(value);
			display->addRow(label, checkBox);
			connect(checkBox, &QCheckBox::clicked, [label, &value](bool checked) { settings.setValue(label, value = checked); });
		}
		for (auto [value, label] : Array<int&, const char*>{
			{ tokenCount, RATE_LIMIT_TOKEN_COUNT },
			{ tokenRestoreDelay, RATE_LIMIT_TOKEN_RESTORE_DELAY },
			{ maxSentenceSize, MAX_SENTENCE_SIZE },
		})
		{
			value = settings.value(label, value).toInt();
			auto spinBox = new QSpinBox(this);
			spinBox->setRange(0, INT_MAX);
			spinBox->setValue(value);
			display->addRow(label, spinBox);
			connect(spinBox, qOverload<int>(&QSpinBox::valueChanged), [label, &value](int newValue) { settings.setValue(label, value = newValue); });
		}
		if (GET_API_KEY_FROM)
		{
			auto keyEdit = new QLineEdit(settings.value(API_KEY).toString(), this);
			authKey->assign(S(keyEdit->text()));
			QObject::connect(keyEdit, &QLineEdit::textChanged, [](QString key) { settings.setValue(API_KEY, S(authKey->assign(S(key)))); });
			auto keyLabel = new QLabel(QString("<a href=\"%1\">%2</a>").arg(GET_API_KEY_FROM, API_KEY), this);
			keyLabel->setOpenExternalLinks(true);
			display->addRow(keyLabel, keyEdit);
		}

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
	}

	~Window()
	{
		SaveCache();
	}

private:
	void SaveTranslateTo(QString language)
	{
		settings.setValue(TRANSLATE_TO, S(translateTo->assign(S(language.split(": ")[1]))));
	}
	void SaveTranslateFrom(QString language)
	{
		settings.setValue(TRANSLATE_FROM, S(translateFrom->assign(S(language.split(": ")[1]))));
	}
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0 || sentence.size() > maxSentenceSize) return false;

	static class
	{
	public:
		bool Request()
		{
			auto tokens = this->tokens.Acquire();
			tokens->push_back(GetTickCount());
			if (tokens->size() > tokenCount * 5) tokens->erase(tokens->begin(), tokens->begin() + tokenCount * 3);
			tokens->erase(std::remove_if(tokens->begin(), tokens->end(), [](DWORD token) { return GetTickCount() - token > tokenRestoreDelay; }), tokens->end());
			return tokens->size() < tokenCount;
		}

	private:
		Synchronized<std::vector<DWORD>> tokens;
	} rateLimiter;

	auto StripWhitespace = [](std::wstring& text)
	{
		text.erase(text.begin(), std::find_if_not(text.begin(), text.end(), iswspace));
		text.erase(std::find_if_not(text.rbegin(), text.rend(), iswspace).base(), text.end());
	};

	bool cache = false;
	std::wstring translation;
	StripWhitespace(sentence);
	if (useCache)
	{
		auto translationCache = ::translationCache.Acquire();
		if (auto it = translationCache->find(sentence); it != translationCache->end()) translation = it->second + L"\x200b"; // dumb hack to not try to translate if stored empty translation
	}
	if (translation.empty() && (!translateSelectedOnly || sentenceInfo["current select"]))
		if (rateLimiter.Request() || !rateLimitAll || (!rateLimitSelected && sentenceInfo["current select"])) std::tie(cache, translation) = Translate(sentence);
		else translation = TOO_MANY_TRANS_REQUESTS;
	StripWhitespace(translation);
	if (cache) translationCache->try_emplace(sentence, translation);
	if (cache && translationCache->size() > savedSize + 50) SaveCache();

	for (int i = 0; i < translation.size(); ++i) if (translation[i] == '\r' && translation[i + 1] == '\n') translation[i] = 0x200b; // for some reason \r appears as newline - no need to double
	if (!translation.empty()) (sentence += L"\x200b \n") += translation;
	return true;
}

TEST(assert(Translate(L"こんにちは").second.find(L"ello") != std::string::npos));

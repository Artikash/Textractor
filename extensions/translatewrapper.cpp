#include "qtcommon.h"
#include "extension.h"
#include "blockmarkup.h"
#include "network.h"
#include <map>
#include <fstream>
#include <QComboBox>

extern const char* NATIVE_LANGUAGE;
extern const char* TRANSLATE_TO;
extern const wchar_t* TOO_MANY_TRANS_REQUESTS;

extern const char* TRANSLATION_PROVIDER;
extern QStringList languages;
std::pair<bool, std::wstring> Translate(const std::wstring& text);

const char* LANGUAGE = u8"Language";
const std::string TRANSLATION_CACHE_FILE = FormatString("%s Cache.txt", TRANSLATION_PROVIDER);

QFormLayout* display;
QSettings settings = openSettings();
Synchronized<std::wstring> translateTo = L"en";

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
		connect(languageBox, &QComboBox::currentTextChanged, this, &Window::saveLanguage);
		display->addRow(TRANSLATE_TO, languageBox);

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
	void saveLanguage(QString language)
	{
		settings.setValue(LANGUAGE, S(translateTo->assign(S(language.split(": ")[1]))));
	}
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["text number"] == 0) return false;

	static class
	{
	public:
		bool Request()
		{
			auto tokens = this->tokens.Acquire();
			tokens->push_back(GetTickCount());
			if (tokens->size() > tokenCount * 5) tokens->erase(tokens->begin(), tokens->begin() + tokenCount * 3);
			tokens->erase(std::remove_if(tokens->begin(), tokens->end(), [this](DWORD token) { return GetTickCount() - token > delay; }), tokens->end());
			return tokens->size() < tokenCount;
		}

	private:
		const int tokenCount = 30, delay = 60 * 1000;
		Synchronized<std::vector<DWORD>> tokens;
	} rateLimiter;

	bool cache = false;
	std::wstring translation;
	{
		auto translationCache = ::translationCache.Acquire();
		auto translationLocation = translationCache->find(sentence);
		if (translationLocation != translationCache->end()) translation = translationLocation->second;
		else if (!(rateLimiter.Request() || sentenceInfo["current select"])) translation = TOO_MANY_TRANS_REQUESTS;
		else std::tie(cache, translation) = Translate(sentence);
		if (cache && sentenceInfo["current select"]) translationCache->try_emplace(translationLocation, sentence, translation);
	}
	if (cache && translationCache->size() > savedSize + 50) SaveCache();

	Unescape(translation);
	sentence += L"\n" + translation;
	return true;
}

TEST(
	assert(Translate(L"こんにちは").second.find(L"ello") != std::wstring::npos)
);

#include "qtcommon.h"
#include "extension.h"
#include "defs.h"
#include "network.h"
#include <map>
#include <QTimer>

extern const char* SELECT_LANGUAGE;
extern const char* SELECT_LANGUAGE_MESSAGE;
extern const char* LANGUAGE_SAVED;
extern const wchar_t* TOO_MANY_TRANS_REQUESTS;

extern const char* TRANSLATION_PROVIDER;
extern QStringList languages;
std::pair<bool, std::wstring> Translate(const std::wstring& text);

const char* LANGUAGE = u8"Language";
const QString CACHE_FILE = QString("%1 Cache.txt").arg(TRANSLATION_PROVIDER);

Synchronized<std::wstring> translateTo = L"en";
QSettings settings(CONFIG_FILE, QSettings::IniFormat);
int savedSize;
Synchronized<std::map<std::wstring, std::wstring>> translationCache;

void SaveCache()
{
	QTextFile file(CACHE_FILE, QIODevice::WriteOnly | QIODevice::Truncate);
	auto translationCache = ::translationCache.Acquire();
	for (const auto& [original, translation] : translationCache.contents)
		file.write(S(FormatString(L"%s|T|\n%s|T|\n", original, translation)).toUtf8());
	savedSize = translationCache->size();
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		settings.beginGroup(TRANSLATION_PROVIDER);
		if (settings.contains(LANGUAGE)) translateTo->assign(S(settings.value(LANGUAGE).toString()));
		else QTimer::singleShot(0, []
		{
			QString language = QInputDialog::getItem(
				nullptr,
				SELECT_LANGUAGE,
				QString(SELECT_LANGUAGE_MESSAGE).arg(TRANSLATION_PROVIDER),
				languages,
				0,
				false,
				nullptr,
				Qt::WindowCloseButtonHint
			);
			translateTo->assign(S(language.split(": ")[1]));
			settings.setValue(LANGUAGE, S(translateTo->c_str()));
			QMessageBox::information(nullptr, SELECT_LANGUAGE, QString(LANGUAGE_SAVED).arg(CONFIG_FILE));
		});

		QStringList savedCache = QString(QTextFile(CACHE_FILE, QIODevice::ReadOnly).readAll()).split("|T|\n", QString::SkipEmptyParts);
		for (int i = 0; i < savedCache.size() - 1; i += 2)
			translationCache->insert({ S(savedCache[i]), S(savedCache[i + 1]) });
		savedSize = translationCache->size();
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		SaveCache();
	}
	break;
	}
	return TRUE;
}

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
	if (translationCache->count(sentence) != 0) translation = translationCache->at(sentence);
	else if (!(rateLimiter.Request() || sentenceInfo["current select"])) translation = TOO_MANY_TRANS_REQUESTS;
	else std::tie(cache, translation) = Translate(sentence);
	if (cache && sentenceInfo["current select"])
	{
		translationCache->insert({ sentence, translation });
		if (translationCache->size() > savedSize + 50) SaveCache();
	}

	Unescape(translation);
	sentence += L"\n" + translation;
	return true;
}

TEST(
	assert(Translate(L"こんにちは").second.find(L"ello") != std::wstring::npos)
);

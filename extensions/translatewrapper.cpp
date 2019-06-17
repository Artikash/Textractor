#include "extension.h"
#include "network.h"
#include <QTimer>
#include <QInputDialog>
#include <QFile>

extern const char* SELECT_LANGUAGE;
extern const char* SELECT_LANGUAGE_MESSAGE;
extern const wchar_t* TOO_MANY_TRANS_REQUESTS;

extern const char* TRANSLATION_PROVIDER;
extern QStringList languages;
extern Synchronized<std::wstring> translateTo;
std::pair<bool, std::wstring> Translate(const std::wstring& text);

Synchronized<std::unordered_map<std::wstring, std::wstring>> translationCache;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		QTimer::singleShot(0, []
		{
			translateTo->assign(QInputDialog::getItem(
				nullptr,
				SELECT_LANGUAGE,
				QString(SELECT_LANGUAGE_MESSAGE).arg(TRANSLATION_PROVIDER),
				languages,
				0,
				false,
				nullptr,
				Qt::WindowCloseButtonHint)
				.split(": ")[1]
				.toStdWString()
			);
		});

		QFile file(QString("%1 Cache.txt").arg(TRANSLATION_PROVIDER));
		file.open(QIODevice::ReadOnly | QIODevice::Text);
		QStringList savedCache = QString(file.readAll()).split("|T|\n", QString::SkipEmptyParts);
		for (int i = 0; i < savedCache.size() - 1; i += 2)
			translationCache->insert({ savedCache[i].toStdWString(), savedCache[i + 1].toStdWString() });
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		QFile file(QString("%1 Cache.txt").arg(TRANSLATION_PROVIDER));
		file.open(QIODevice::WriteOnly | QIODevice::Text);
		auto translationCache = ::translationCache.Acquire();
		for (const auto& [original, translation] : translationCache.contents)
			file.write(QString::fromStdWString(FormatString(L"%s|T|\n%s|T|\n", original, translation)).toUtf8());
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
	if (cache) translationCache->insert({ sentence, translation });
	Unescape(translation);

	sentence += L"\n" + translation;
	return true;
}

TEST(
	{
		std::wstring test = L"こんにちは";
		ProcessSentence(test, { SentenceInfo::DUMMY });
		assert(test.find(L"Hello") != std::wstring::npos);
	}
);

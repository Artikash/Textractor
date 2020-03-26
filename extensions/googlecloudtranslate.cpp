#include "qtcommon.h"
#include "extension.h"
#include "network.h"

extern const wchar_t* TRANSLATION_ERROR;
extern const char* API_KEY;

extern QFormLayout* display;
extern QSettings settings;
extern Synchronized<std::wstring> translateTo;

const char* TRANSLATION_PROVIDER = "Google Cloud Translate";
QStringList languages
{
	"Afrikaans: af",
	"Arabic: ar",
	"Albanian: sq",
	"Belarusian: be",
	"Bengali: bn",
	"Bosnian: bs",
	"Bulgarian: bg",
	"Catalan: ca",
	"Chinese(Simplified): zh-CH",
	"Chinese(Traditional): zh-TW",
	"Croatian: hr",
	"Czech: cs",
	"Danish: da",
	"Dutch: nl",
	"English: en",
	"Esperanto: eo",
	"Estonian: et",
	"Filipino: tl",
	"Finnish: fi",
	"French: fr",
	"Galician: gl",
	"German: de",
	"Greek: el",
	"Hebrew: iw",
	"Hindi: hi",
	"Hungarian: hu",
	"Icelandic: is",
	"Indonesian: id",
	"Irish: ga",
	"Italian: it",
	"Japanese: ja",
	"Klingon: tlh",
	"Korean: ko",
	"Latin: la",
	"Latvian: lv",
	"Lithuanian: lt",
	"Macedonian: mk",
	"Malay: ms",
	"Maltese: mt",
	"Norwegian: no",
	"Persian: fa",
	"Polish: pl",
	"Portuguese: pt",
	"Romanian: ro",
	"Russian: ru",
	"Serbian: sr",
	"Slovak: sk",
	"Slovenian: sl",
	"Somali: so",
	"Spanish: es",
	"Swahili: sw",
	"Swedish: sv",
	"Thai: th",
	"Turkish: tr",
	"Ukranian: uk",
	"Urdu: ur",
	"Vietnamese: vi",
	"Welsh: cy",
	"Yiddish: yi",
	"Zulu: zu"
};

Synchronized<std::wstring> key;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		auto keyInput = new QLineEdit(settings.value(API_KEY).toString());
		key->assign(S(keyInput->text()));
		QObject::connect(keyInput, &QLineEdit::textChanged, [](QString key) { settings.setValue(API_KEY, S(::key->assign(S(key)))); });
		display->addRow(API_KEY, keyInput);
		auto googleCloudInfo = new QLabel(
			"<a href=\"https://codelabs.developers.google.com/codelabs/cloud-translation-intro\">https://codelabs.developers.google.com/codelabs/cloud-translation-intro</a>"
		);
		googleCloudInfo->setOpenExternalLinks(true);
		display->addRow(googleCloudInfo);
	}
	break;
	case DLL_PROCESS_DETACH:
	{
	}
	break;
	}
	return TRUE;
}

std::pair<bool, std::wstring> Translate(const std::wstring& text, SentenceInfo)
{

	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"translation.googleapis.com",
		L"GET",
		FormatString(L"/language/translate/v2?format=text&q=%s&target=%s&key=%s", Escape(text), translateTo->c_str(), key->c_str()).c_str()
	})
	{
		// Response formatted as JSON: starts with "translatedText": " and translation is enclosed in quotes followed by a comma
		if (std::wsmatch results; std::regex_search(httpRequest.response, results, std::wregex(L"\"translatedText\": \"(.+?)\","))) return { true, results[1] };
		return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
	}
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

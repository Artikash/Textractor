#include "qtcommon.h"
#include "devtools.h"

extern const wchar_t* ERROR_START_CHROME;
extern const wchar_t* TRANSLATION_ERROR;

extern Synchronized<std::wstring> translateTo, translateFrom;

const char* TRANSLATION_PROVIDER = "DevTools DeepL Translate";
const char* GET_API_KEY_FROM = nullptr;
bool translateSelectedOnly = true, rateLimitAll = false, rateLimitSelected = false, useCache = true, useFilter = true;
int tokenCount = 30, tokenRestoreDelay = 60000, maxSentenceSize = 2500;

QStringList languages
{
	"Bulgarian: BG",
	"Chinese: ZH",
	"Czech: CS",
	"Danish: DA",
	"Dutch: NL",
	"English: EN",
	"Estonian: ET",
	"Finnish: FI",
	"French: FR",
	"German: DE",
	"Greek: EL",
	"Hungarian: HU",
	"Italian: IT",
	"Japanese: JA",
	"Latvian: LV",
	"Lithuanian: LT",
	"Polish: PL",
	"Portuguese: PT",
	"Romanian: RO",
	"Russian: RU",
	"Slovak: SK",
	"Slovenian: SL",
	"Spanish: ES",
	"Swedish: SV"
};
std::wstring autoDetectLanguage = L"auto";

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DevTools::Start();
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		DevTools::Close();
	}
	break;
	}
	return TRUE;
}

std::pair<bool, std::wstring> Translate(const std::wstring& text)
{
	if (!DevTools::Connected()) return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, ERROR_START_CHROME) };
	// DevTools can't handle concurrent translations yet
	static std::mutex translationMutex;
	std::scoped_lock lock(translationMutex);
	DevTools::SendRequest("Page.navigate", FormatString(LR"({"url":"https://www.deepl.com/en/translator#%s/%s/%s"})", translateTo.Copy(), translateTo.Copy(), Escape(text)));

	if (translateFrom.Copy() != autoDetectLanguage)
		DevTools::SendRequest("Runtime.evaluate", FormatString(LR"({"expression":"
			document.querySelector('.lmt__language_select--source').querySelector('button').click();
			document.evaluate(`//button[contains(text(),'%s')]`,document.querySelector('.lmt__language_select__menu'),null,XPathResult.FIRST_ORDERED_NODE_TYPE,null).singleNodeValue.click();
		"})", S(std::find_if(languages.begin(), languages.end(), [end = S(translateFrom.Copy())](const QString& language) { return language.endsWith(end); })->split(":")[0])));

	for (int retry = 0; ++retry < 100; Sleep(100))
		if (auto translation = Copy(DevTools::SendRequest("Runtime.evaluate",
			LR"({"expression":"document.querySelector('#target-dummydiv').innerHTML.trim() ","returnByValue":true})"
		)[L"result"][L"value"].String())) if (!translation->empty()) return { true, translation.value() };
	if (auto errorMessage = Copy(DevTools::SendRequest("Runtime.evaluate",
		LR"({"expression":"document.querySelector('div.lmt__system_notification').innerHTML","returnByValue":true})"
	)[L"result"][L"value"].String())) return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, errorMessage.value()) };
	return { false, TRANSLATION_ERROR };
}

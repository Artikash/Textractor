#include "qtcommon.h"
#include "translatewrapper.h"
#include "devtools.h"

extern const wchar_t* ERROR_START_CHROME;
extern const wchar_t* TRANSLATION_ERROR;

const char* TRANSLATION_PROVIDER = "DevTools DeepL Translate";
const char* GET_API_KEY_FROM = nullptr;
std::wstring currTranslateTo;

extern const QStringList languagesTo
{
	"Bulgarian",
	"Chinese (Simplified)",
	"Czech",
	"Danish",
	"Dutch",
	"English (American)",
	"English (British)",
	"Estonian",
	"Finnish",
	"French",
	"German",
	"Greek",
	"Hungarian",
	"Indonesian",
	"Italian",
	"Japanese",
	"Korean",
	"Latvian",
	"Lithuanian",
	"Norwegian",
	"Polish",
	"Portuguese",
	"Portuguese (Brazilian)",
	"Romanian",
	"Russian",
	"Slovak",
	"Slovenian",
	"Spanish",
	"Swedish",
	"Turkish",
	"Ukrainian"
},
languagesFrom =
{
	"Bulgarian",
	"Chinese",
	"Czech",
	"Danish",
	"Dutch",
	"English",
	"Estonian",
	"Finnish",
	"French",
	"German",
	"Greek",
	"Hungarian",
	"Indonesian",
	"Italian",
	"Japanese",
	"Korean",
	"Latvian",
	"Lithuanian",
	"Norwegian",
	"Polish",
	"Portuguese",
	"Romanian",
	"Russian",
	"Slovak",
	"Slovenian",
	"Spanish",
	"Swedish",
	"Turkish",
	"Ukrainian"
};
extern const std::unordered_map<std::wstring, std::wstring> codes
{
	{ { L"Bulgarian" }, { L"bg-BG" } },
	{ { L"Chinese" }, { L"zh" } },
	{ { L"Chinese (Simplified)" }, { L"zh-ZH" } },
	{ { L"Czech" }, { L"cs-CS" } },
	{ { L"Danish" }, { L"da-DA" } },
	{ { L"Dutch" }, { L"nl-NL" } },
	{ { L"English" }, { L"en" } },
	{ { L"English (American)" }, { L"en-US" } },
	{ { L"English (British)" }, { L"en-GB" } },
	{ { L"Estonian" }, { L"et-ET" } },
	{ { L"Finnish" }, { L"fi-FI" } },
	{ { L"French" }, { L"fr-FR" } },
	{ { L"German" }, { L"de-DE" } },
	{ { L"Greek" }, { L"el-EL" } },
	{ { L"Hungarian" }, { L"hu-HU" } },
	{ { L"Indonesian" }, { L"id-ID" } },
	{ { L"Italian" }, { L"it-IT" } },
	{ { L"Japanese" }, { L"ja-JA" } },
	{ { L"Korean" }, { L"ko-KO" } },
	{ { L"Latvian" }, { L"lv-LV" } },
	{ { L"Lithuanian" }, { L"lt-LT" } },
	{ { L"Norwegian" }, { L"nb-NB" } },
	{ { L"Polish" }, { L"pl-PL" } },
	{ { L"Portuguese" }, { L"pt-PT" } },
	{ { L"Portuguese (Brazilian)" }, { L"pt-BR" } },
	{ { L"Romanian" }, { L"ro-RO" } },
	{ { L"Russian" }, { L"ru-RU" } },
	{ { L"Slovak" }, { L"sk-SK" } },
	{ { L"Slovenian" }, { L"sl-SL" } },
	{ { L"Spanish" }, { L"es-ES" } },
	{ { L"Swedish" }, { L"sv-SV" } },
	{ { L"Turkish" }, { L"tr-TR" } },
	{ { L"Ukrainian" }, { L"uk-UK" } },
	{ { L"?" }, { L"auto" } }
};

bool translateSelectedOnly = true, useRateLimiter = true, rateLimitSelected = false, useCache = true, useFilter = true;
int tokenCount = 30, rateLimitTimespan = 60000, maxSentenceSize = 2500;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DevTools::Initialize();
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

std::wstring htmlDecode (std::wstring text) {
    const std::wstring enc[] = { L"&amp;", L"&lt;", L"&gt;" };
    const std::wstring dec[] = { L"&", L"<", L">" };
	
	size_t pos;
	for(int j = 0; j < 3; j++) {
		do {
			pos = text.find(enc[j]);
	  		if (pos != std::wstring::npos)
		    		text.replace (pos,enc[j].length(),dec[j]);
    		} while (pos != std::wstring::npos);
  	}
	return text;
}

std::pair<bool, std::wstring> Translate(const std::wstring& text, TranslationParam tlp)
{
	if (!DevTools::Connected()) return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, ERROR_START_CHROME) };
	// DevTools can't handle concurrent translations yet
	static std::mutex translationMutex;
	std::scoped_lock lock(translationMutex);
	std::wstring escaped; // DeepL breaks with slash in input
	for (auto ch : text) ch == '/' ? escaped += L"\\/" : escaped += ch;
	if (currTranslateTo == tlp.translateTo)
		DevTools::SendRequest("Page.navigate", FormatString(LR"({"url":"https://www.deepl.com/en/translator#%s/%s/%s"})", (tlp.translateFrom == L"?") ? codes.at(tlp.translateFrom) : codes.at(tlp.translateFrom).substr(0, 2), codes.at(tlp.translateTo).substr(0, 2), Escape(escaped)));
	else
	{
		currTranslateTo = tlp.translateTo;
		DevTools::SendRequest("Page.navigate", FormatString(LR"({"url":"https://www.deepl.com/en/translator#%s/%s/%s"})", (tlp.translateFrom == L"?") ? codes.at(tlp.translateFrom) : codes.at(tlp.translateFrom).substr(0, 2), codes.at(tlp.translateTo), Escape(escaped)));
	}

	for (int retry = 0; ++retry < 100; Sleep(100))
		if (auto translation = Copy(DevTools::SendRequest("Runtime.evaluate",
			LR"({"expression":"document.querySelector('[data-testid=translator-target-input]').textContent.trim() ","returnByValue":true})"
		)[L"result"][L"value"].String())) if (!translation->empty()) return { true, htmlDecode(translation.value()) };
	if (auto errorMessage = Copy(DevTools::SendRequest("Runtime.evaluate",
		LR"({"expression":"document.querySelector('div.lmt__system_notification').innerHTML","returnByValue":true})"
	)[L"result"][L"value"].String())) return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, errorMessage.value()) };
	return { false, TRANSLATION_ERROR };
}

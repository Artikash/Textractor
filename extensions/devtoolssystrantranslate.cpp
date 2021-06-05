#include "qtcommon.h"
#include "devtools.h"

extern const wchar_t* ERROR_START_CHROME;
extern const wchar_t* TRANSLATION_ERROR;

extern Synchronized<std::wstring> translateTo, translateFrom;
extern QFormLayout* display;
extern Settings settings;

const char* TRANSLATION_PROVIDER = "DevTools Systran Translate";
const char* GET_API_KEY_FROM = nullptr;
bool translateSelectedOnly = true, rateLimitAll = false, rateLimitSelected = false, useCache = true, useFilter = true;
int tokenCount = 30, tokenRestoreDelay = 60000, maxSentenceSize = 2500;

QStringList languages
{
	"Chinese: zh",
	"Chinese (traditional): zt",
	"English: en",
	"French: fr",
	"German: de",
	"Italian: it",
	"Japanese: ja",
	"Korean: ko",
	"Portuguese: pt",
	"Spanish: es",
	"Thai: th",
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

	DevTools::SendRequest("Page.navigate", FormatString(LR"({"url":"https://translate.systran.net/?&source=%s&target=%s&input=%s"})", translateFrom.Copy(), translateTo.Copy(), Escape(text)));
	for (int retry = 0; ++retry < 100; Sleep(100))
		if (auto translation = Copy(DevTools::SendRequest("Runtime.evaluate",
			LR"({"expression":"document.querySelector('#outputEditor').textContent.trim() ","returnByValue":true})"
		)[L"result"][L"value"].String())) if (!translation->empty()) return { true, translation.value() };
	return { false, TRANSLATION_ERROR };
}

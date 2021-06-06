#include "qtcommon.h"
#include "devtools.h"

extern const wchar_t* ERROR_START_CHROME;
extern const wchar_t* TRANSLATION_ERROR;

extern Synchronized<std::wstring> translateTo, translateFrom;

const char* TRANSLATION_PROVIDER = "DevTools Papago Translate";
const char* GET_API_KEY_FROM = nullptr;
bool translateSelectedOnly = true, rateLimitAll = false, rateLimitSelected = false, useCache = true, useFilter = true;
int tokenCount = 30, tokenRestoreDelay = 60000, maxSentenceSize = 2500;

QStringList languages
{
	"Chinese (simplified): zh-CN",
	"Chinese (traditional): zt-TW",
	"English: en",
	"French: fr",
	"German: de",
	"Hindi: hi",
	"Indonesian: id",
	"Italian: it",
	"Japanese: ja",
	"Korean: ko",
	"Portuguese: pt",
	"Russian: ru",
	"Spanish: es",
	"Thai: th",
	"Vietnamese: vi",
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
	DevTools::SendRequest("Page.navigate", FormatString(LR"({"url":"https://papago.naver.com/?sk=%s&tk=%s&st=%s"})", translateFrom.Copy(), translateTo.Copy(), Escape(text)));
	for (int retry = 0; ++retry < 100; Sleep(100))
		if (auto translation = Copy(DevTools::SendRequest("Runtime.evaluate",
			LR"({"expression":"document.querySelector('#txtTarget').textContent.trim() ","returnByValue":true})"
		)[L"result"][L"value"].String())) if (!translation->empty()) return { true, translation.value() };
	return { false, TRANSLATION_ERROR };
}

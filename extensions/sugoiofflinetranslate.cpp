#include "qtcommon.h"
#include "translatewrapper.h"
#include "network.h"

extern const wchar_t* TRANSLATION_ERROR;
extern const char* SUGOI_HOST;
extern const char* SUGOI_PORT;
extern QFormLayout* display;
extern Settings settings;

const char* TRANSLATION_PROVIDER = "Sugoi Offline Translate";
const char* GET_API_KEY_FROM = nullptr;
extern const QStringList languagesTo
{
   "English"
},
languagesFrom
{
	"Japanese"
};

bool translateSelectedOnly = false, useRateLimiter = true, rateLimitSelected = false, useCache = true, useFilter = true;
int tokenCount = 30, rateLimitTimespan = 60000, maxSentenceSize = 1000;
QString sugoiHost, sugoiPort;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		sugoiHost = settings.value(SUGOI_HOST).toString();
		if (sugoiHost.isEmpty()) sugoiHost = "localhost";
		auto sugoiHostEdit = new QLineEdit(sugoiHost);
		QObject::connect(sugoiHostEdit, &QLineEdit::textChanged, [sugoiHostEdit](QString newValue) { settings.setValue(SUGOI_HOST, sugoiHost =  newValue); });
		display->addRow(SUGOI_HOST, sugoiHostEdit);

		sugoiPort = settings.value(SUGOI_PORT).toString();
		if (sugoiPort.isEmpty()) sugoiPort = "14366";
		auto sugoiPortEdit = new QLineEdit(sugoiPort);
		QObject::connect(sugoiPortEdit, &QLineEdit::textChanged, [sugoiPortEdit](QString newValue) { settings.setValue(SUGOI_PORT, sugoiPort =  newValue); });
		display->addRow(SUGOI_PORT, sugoiPortEdit);
	}
	break;
	}
	return TRUE;
}

std::pair<bool, std::wstring> Translate(const std::wstring& text, TranslationParam tlp)
{
	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		sugoiHost.toStdWString().c_str(),
		L"POST",
		NULL,
		FormatString(R"({"content":"%s","message":"translate sentences"})", JSON::Escape(WideStringToString(text))),
		L"Content-type: application/json",
		sugoiPort.toUInt(),
		NULL,
		0
		})
		if (auto translation = Copy(JSON::Parse(httpRequest.response).String())) return { true, std::regex_replace(translation.value(), std::wregex(L"<unk>"), L" ") };
		else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

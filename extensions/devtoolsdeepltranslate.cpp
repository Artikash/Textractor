#include "qtcommon.h"
#include "devtools.h"
#include <ShlObj.h>

extern const wchar_t* TRANSLATION_ERROR;
extern Synchronized<std::wstring> translateTo;
extern QFormLayout* display;
extern Settings settings;

const char* TRANSLATION_PROVIDER = "DevTools DeepL Translate";
const char* GET_API_KEY_FROM = nullptr;
bool translateSelectedOnly = true, rateLimitAll = false, rateLimitSelected = false, useCache = true;
int tokenCount = 30, tokenRestoreDelay = 60000, maxSentenceSize = 10000;

extern const char* CHROME_LOCATION;
extern const char* START_DEVTOOLS;
extern const char* STOP_DEVTOOLS;
extern const char* HEADLESS_MODE;
extern const char* DEVTOOLS_STATUS;
extern const char* AUTO_START;
extern const wchar_t* ERROR_START_CHROME;

QStringList languages
{
	"Chinese (simplified): zh",
	"Dutch: nl",
	"English: en",
	"French: fr",
	"German: de",
	"Italian: it",
	"Japanese: ja",
	"Polish: pl",
	"Portuguese: pt",
	"Russian: ru",
	"Spanish: es",
};

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		QString chromePath = settings.value(CHROME_LOCATION).toString();
		wchar_t programFiles[MAX_PATH + 100] = {};
		if (chromePath.isEmpty()) for (auto folder : { CSIDL_PROGRAM_FILESX86, CSIDL_PROGRAM_FILES, CSIDL_LOCAL_APPDATA })
		{
			SHGetFolderPathW(NULL, folder, NULL, SHGFP_TYPE_CURRENT, programFiles);
			wcscat_s(programFiles, L"/Google/Chrome/Application/chrome.exe");
			if (std::filesystem::exists(programFiles)) chromePath = S(programFiles);
		}
		auto chromePathEdit = new QLineEdit(chromePath);
		QObject::connect(chromePathEdit, &QLineEdit::textChanged, [chromePathEdit](QString path) { settings.setValue(CHROME_LOCATION, path); });
		display->addRow(CHROME_LOCATION, chromePathEdit);
		auto statusLabel = new QLabel("Stopped");
		auto startButton = new QPushButton(START_DEVTOOLS), stopButton = new QPushButton(STOP_DEVTOOLS);
		auto headlessCheckBox = new QCheckBox(HEADLESS_MODE);
		headlessCheckBox->setChecked(settings.value(HEADLESS_MODE, true).toBool());
		QObject::connect(headlessCheckBox, &QCheckBox::clicked, [](bool headless) { settings.setValue(HEADLESS_MODE, headless); });
		QObject::connect(startButton, &QPushButton::clicked, [statusLabel, chromePathEdit, headlessCheckBox] {
			DevTools::Start(
				S(chromePathEdit->text()),
				[statusLabel](QString status) { QMetaObject::invokeMethod(statusLabel, std::bind(&QLabel::setText, statusLabel, status)); },
				headlessCheckBox->isChecked(),
				9222
			);
			if (!DevTools::SendRequest(L"Network.enable")) DevTools::Close();
		});
		QObject::connect(stopButton, &QPushButton::clicked, &DevTools::Close);
		auto buttons = new QHBoxLayout();
		buttons->addWidget(startButton);
		buttons->addWidget(stopButton);
		display->addRow(buttons);
		display->addRow(headlessCheckBox);
		auto autoStartButton = new QCheckBox(AUTO_START);
		autoStartButton->setChecked(settings.value(AUTO_START, false).toBool());
		QObject::connect(autoStartButton, &QCheckBox::clicked, [](bool autoStart) {settings.setValue(AUTO_START, autoStart); });
		display->addRow(autoStartButton);
		statusLabel->setFrameStyle(QFrame::Panel | QFrame::Sunken);
		display->addRow(DEVTOOLS_STATUS, statusLabel);
		if (autoStartButton->isChecked()) startButton->click();
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

	// Navigate to site and wait until it is loaded
	DevTools::StartListening(L"Network.responseReceived");
	DevTools::SendRequest(L"Page.navigate", FormatString(LR"({"url":"https://www.deepl.com/translator#any/%s/%s"})", translateTo.Copy(), Escape(text)));
	for (int retry = 0; ++retry < 50; Sleep(100))
		for (const auto& result : DevTools::ListenResults(L"Network.responseReceived"))
			if (auto URL = result[L"response"][L"url"].String())
				if (URL->find(L"deepl.com/jsonrpc") != std::string::npos) break;
	DevTools::StopListening(L"Network.responseReceived");

	// Extract translation from site
	auto RemoveTags = [](const std::wstring& HTML)
	{
		std::wstring result;
		for (unsigned i = 0; i < HTML.size(); ++i)
			if (HTML[i] == '<') i = HTML.find('>', i);
			else result.push_back(HTML[i]);
		return result;
	};
	if (auto document = Copy(DevTools::SendRequest(L"DOM.getDocument")[L"root"][L"nodeId"].Number()))
		if (auto target = Copy(DevTools::SendRequest(
			L"DOM.querySelector", FormatString(LR"({"nodeId":%d,"selector":"#target-dummydiv"})", (int)document.value())
		)[L"nodeId"].Number()))
			if (auto outerHTML = Copy(DevTools::SendRequest(L"DOM.getOuterHTML", FormatString(LR"({"nodeId":%d})", (int)target.value()))[L"outerHTML"].String()))
				if (auto translation = RemoveTags(outerHTML.value()); !translation.empty()) return { true, translation };
				else if (target = Copy(DevTools::SendRequest(
					L"DOM.querySelector", FormatString(LR"({"nodeId":%d,"selector":"div.lmt__system_notification"})", (int)document.value())
				)[L"nodeId"].Number()))
					if (outerHTML = Copy(DevTools::SendRequest(L"DOM.getOuterHTML", FormatString(LR"({"nodeId":%d})", (int)target.value()))[L"outerHTML"].String()))
						return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, RemoveTags(outerHTML.value())) };
	return { false, TRANSLATION_ERROR };
}
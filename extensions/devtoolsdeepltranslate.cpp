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
int tokenCount = 30, tokenRestoreDelay = 60000, maxSentenceSize = 2500;

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
		auto headlessCheck = new QCheckBox();
		headlessCheck->setChecked(settings.value(HEADLESS_MODE, true).toBool());
		QObject::connect(headlessCheck, &QCheckBox::clicked, [](bool headless) { settings.setValue(HEADLESS_MODE, headless); });
		QObject::connect(startButton, &QPushButton::clicked, [statusLabel, chromePathEdit, headlessCheck] {
			DevTools::Start(
				S(chromePathEdit->text()),
				[statusLabel](QString status)
				{
					QMetaObject::invokeMethod(statusLabel, std::bind(&QLabel::setText, statusLabel, status));
					if (status == "ConnectedState") std::thread([]
					{
						if (HttpRequest httpRequest{
							L"Mozilla/5.0 Textractor",
							L"127.0.0.1",
							L"POST",
							L"/json/version",
							"",
							NULL,
							9222,
							NULL,
							WINHTTP_FLAG_ESCAPE_DISABLE
						})
							if (auto userAgent = Copy(JSON::Parse(httpRequest.response)[L"User-Agent"].String()))
								if (userAgent->find(L"Headless") != std::string::npos)
									DevTools::SendRequest(L"Network.setUserAgentOverride",
										FormatString(LR"({"userAgent":"%s"})", userAgent->replace(userAgent->find(L"Headless"), 8, L"")));
					}).detach();
				},
				headlessCheck->isChecked()
			);
		});
		QObject::connect(stopButton, &QPushButton::clicked, &DevTools::Close);
		auto buttons = new QHBoxLayout();
		buttons->addWidget(startButton);
		buttons->addWidget(stopButton);
		display->addRow(HEADLESS_MODE, headlessCheck);
		auto autoStartButton = new QCheckBox();
		autoStartButton->setChecked(settings.value(AUTO_START, false).toBool());
		QObject::connect(autoStartButton, &QCheckBox::clicked, [](bool autoStart) { settings.setValue(AUTO_START, autoStart); });
		display->addRow(AUTO_START, autoStartButton);
		display->addRow(buttons);
		statusLabel->setFrameStyle(QFrame::Panel | QFrame::Sunken);
		display->addRow(DEVTOOLS_STATUS, statusLabel);
		if (autoStartButton->isChecked()) QMetaObject::invokeMethod(startButton, &QPushButton::click, Qt::QueuedConnection);
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
	DevTools::SendRequest(L"Page.navigate", FormatString(LR"({"url":"https://www.deepl.com/translator#any/%s/%s"})", translateTo.Copy(), Escape(text)));
	for (int retry = 0; ++retry < 100; Sleep(100))
		if (auto translation = Copy(DevTools::SendRequest(
			L"Runtime.evaluate", LR"({"expression":"document.querySelector('#target-dummydiv').innerHTML","returnByValue":true})")[L"result"][L"value"].String())
		) if (!translation->empty()) return { true, translation.value() };
	return { false, TRANSLATION_ERROR };
}
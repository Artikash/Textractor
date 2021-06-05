#include "devtools.h"
#include <QWebSocket>
#include <QMetaEnum>
#include <QFileDialog>
#include <QMouseEvent>
#include <ppltasks.h>
#include <ShlObj.h>

extern const char* CHROME_LOCATION;
extern const char* START_DEVTOOLS;
extern const char* STOP_DEVTOOLS;
extern const char* HEADLESS_MODE;
extern const char* DEVTOOLS_STATUS;
extern const char* AUTO_START;

extern const char* TRANSLATION_PROVIDER;

extern QFormLayout* display;
extern Settings settings;

namespace
{
	auto statusLabel = new QLabel("Stopped");
	PROCESS_INFORMATION processInfo = {};
	std::atomic<int> idCounter = 0;
	std::mutex devToolsMutex;
	QWebSocket webSocket;
	std::unordered_map<int, concurrency::task_completion_event<JSON::Value<wchar_t>>> mapQueue;

	void StatusChanged(QString status)
	{
		QMetaObject::invokeMethod(statusLabel, std::bind(&QLabel::setText, statusLabel, status));
	}
	auto _ = ([]
	{
		QObject::connect(&webSocket, &QWebSocket::stateChanged,
			[](QAbstractSocket::SocketState state) { StatusChanged(QMetaEnum::fromType<QAbstractSocket::SocketState>().valueToKey(state)); });
		QObject::connect(&webSocket, &QWebSocket::textMessageReceived, [](QString message)
		{
			auto result = JSON::Parse(S(message));
			std::scoped_lock lock(devToolsMutex);
			if (auto id = result[L"id"].Number()) if (auto request = mapQueue.find((int)*id); request != mapQueue.end())
			{
				request->second.set(result);
				mapQueue.erase(request);
			}
		});
	}(), 0);
}

namespace DevTools
{
	void Start()
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
		static struct : QObject
		{
			bool eventFilter(QObject* object, QEvent* event)
			{
				if (auto mouseEvent = dynamic_cast<QMouseEvent*>(event))
					if (mouseEvent->button() == Qt::LeftButton)
						if (QString chromePath = QFileDialog::getOpenFileName(nullptr, TRANSLATION_PROVIDER, "/", "Google Chrome (*.exe)"); !chromePath.isEmpty())
							((QLineEdit*)object)->setText(chromePath);
				return false;
			}
		} chromeSelector;
		chromePathEdit->installEventFilter(&chromeSelector);
		QObject::connect(chromePathEdit, &QLineEdit::textChanged, [chromePathEdit](QString path) { settings.setValue(CHROME_LOCATION, path); });
		display->addRow(CHROME_LOCATION, chromePathEdit);
		auto headlessCheck = new QCheckBox();
		auto startButton = new QPushButton(START_DEVTOOLS), stopButton = new QPushButton(STOP_DEVTOOLS);
		headlessCheck->setChecked(settings.value(HEADLESS_MODE, true).toBool());
		QObject::connect(headlessCheck, &QCheckBox::clicked, [](bool headless) { settings.setValue(HEADLESS_MODE, headless); });
		QObject::connect(startButton, &QPushButton::clicked, [chromePathEdit, headlessCheck]
		{
			DWORD exitCode = 0;
			auto args = FormatString(
				L"%s --proxy-server=direct:// --disable-extensions --disable-gpu --user-data-dir=%s\\devtoolscache --remote-debugging-port=9222",
				S(chromePathEdit->text()),
				std::filesystem::current_path().wstring()
			);
			if (headlessCheck->isChecked()) args += L" --headless";
			STARTUPINFOW DUMMY = { sizeof(DUMMY) };
			if ((GetExitCodeProcess(processInfo.hProcess, &exitCode) && exitCode == STILL_ACTIVE) ||
				CreateProcessW(NULL, args.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &DUMMY, &processInfo)
			)
			{
				if (HttpRequest httpRequest{
					L"Mozilla/5.0 Textractor",
					L"127.0.0.1",
					L"POST",
					L"/json/list",
					"",
					NULL,
					9222,
					NULL,
					WINHTTP_FLAG_ESCAPE_DISABLE
				})
				{
					if (auto list = Copy(JSON::Parse(httpRequest.response).Array())) if (auto it = std::find_if(
						list->begin(),
						list->end(),
						[](const JSON::Value<wchar_t>& object) { return object[L"type"].String() && *object[L"type"].String() == L"page" && object[L"webSocketDebuggerUrl"].String(); }
					); it != list->end())
					{
						std::scoped_lock lock(devToolsMutex);
						webSocket.open(S(*(*it)[L"webSocketDebuggerUrl"].String()));
						return;
					}
				}
				StatusChanged("Failed Connection");
			}
			else StatusChanged("Failed Startup");
		});
		QObject::connect(stopButton, &QPushButton::clicked, &Close);
		auto buttons = new QHBoxLayout();
		buttons->addWidget(startButton);
		buttons->addWidget(stopButton);
		display->addRow(HEADLESS_MODE, headlessCheck);
		auto autoStartCheck = new QCheckBox();
		autoStartCheck->setChecked(settings.value(AUTO_START, false).toBool());
		QObject::connect(autoStartCheck, &QCheckBox::clicked, [](bool autoStart) { settings.setValue(AUTO_START, autoStart); });
		display->addRow(AUTO_START, autoStartCheck);
		display->addRow(buttons);
		statusLabel->setFrameStyle(QFrame::Panel | QFrame::Sunken);
		display->addRow(DEVTOOLS_STATUS, statusLabel);
		if (autoStartCheck->isChecked()) QMetaObject::invokeMethod(startButton, &QPushButton::click, Qt::QueuedConnection);
	}

	void Close()
	{
		std::scoped_lock lock(devToolsMutex);
		for (const auto& [_, task] : mapQueue) task.set_exception(std::runtime_error("closed"));
		webSocket.close();
		mapQueue.clear();
		DWORD exitCode = 0;
		if (GetExitCodeProcess(processInfo.hProcess, &exitCode) && exitCode == STILL_ACTIVE)
		{
			TerminateProcess(processInfo.hProcess, 0);
			WaitForSingleObject(processInfo.hProcess, 2000);
			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);
		}
		for (int retry = 0; ++retry < 20; Sleep(100))
    {
			try { std::filesystem::remove_all(L"devtoolscache"); break; }
			catch (std::filesystem::filesystem_error) { continue; }
		} 
		OnStatusChanged("Stopped");
		try { std::filesystem::remove_all(L"devtoolscache"); } catch (std::filesystem::filesystem_error) {}
		StatusChanged("Stopped");
	}

	bool Connected()
	{
		std::scoped_lock lock(devToolsMutex);
		return webSocket.state() == QAbstractSocket::ConnectedState;
	}

	JSON::Value<wchar_t> SendRequest(const char* method, const std::wstring& params)
	{
		concurrency::task_completion_event<JSON::Value<wchar_t>> response;
		int id = idCounter += 1;
		auto message = FormatString(LR"({"id":%d,"method":"%S","params":%s})", id, method, params);
		{
			std::scoped_lock lock(devToolsMutex);
			if (webSocket.state() != QAbstractSocket::ConnectedState) return {};
			mapQueue.try_emplace(id, response);
			webSocket.sendTextMessage(S(message));
			webSocket.flush();
		}
		try { if (auto result = create_task(response).get()[L"result"]) return result; } catch (...) {}
		return {};
	}
}

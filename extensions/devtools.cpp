#include "devtools.h"
#include <QWebSocket>
#include <QMetaEnum>
#include <ppltasks.h>

namespace
{
	std::function<void(QString)> OnStatusChanged = Swallow;
	PROCESS_INFORMATION processInfo = {};
	std::atomic<int> idCounter = 0, idMethod = 0;
	std::mutex devToolsMutex;
	QWebSocket webSocket;
	std::unordered_map<int, concurrency::task_completion_event<JSON::Value<wchar_t>>> mapQueue;
	std::unordered_map<std::wstring, std::vector<JSON::Value<wchar_t>>> mapMethod;
	auto _ = ([]
	{
		QObject::connect(&webSocket, &QWebSocket::stateChanged,
			[](QAbstractSocket::SocketState state) { OnStatusChanged(QMetaEnum::fromType<QAbstractSocket::SocketState>().valueToKey(state)); }
		);
		QObject::connect(&webSocket, &QWebSocket::textMessageReceived, [](QString message)
		{
			auto result = JSON::Parse(S(message));
			std::scoped_lock lock(devToolsMutex);
			if (auto method = result[L"method"].String())
				for (auto& [listenTo, results] : mapMethod) if (*method == listenTo) results.push_back(result[L"params"]);
			if (auto id = result[L"id"].Number())
				if (auto request = mapQueue.find((int)*id); request != mapQueue.end())
					request->second.set(result), mapQueue.erase(request);
		});
	}(), 0);
}

namespace DevTools
{
	void Start(const std::wstring& path, std::function<void(QString)> statusChanged, bool headless, int port)
	{
		OnStatusChanged = statusChanged;
		DWORD exitCode = 0;
		auto args = FormatString(
			L"%s --proxy-server=direct:// --disable-extensions --disable-gpu --user-data-dir=%s\\devtoolscache --remote-debugging-port=%d",
			path,
			std::filesystem::current_path().wstring(),
			port
		);
		if (headless) args += L"--headless";
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
				(DWORD)port,
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
					if (HttpRequest httpRequest{
						L"Mozilla/5.0 Textractor",
						L"127.0.0.1",
						L"POST",
						L"/json/version",
						"",
						NULL,
						(DWORD)port,
						NULL,
						WINHTTP_FLAG_ESCAPE_DISABLE
					})
						if (auto userAgent = Copy(JSON::Parse(httpRequest.response)[L"User-Agent"].String()))
							if (userAgent->find(L"Headless") != std::string::npos)
								SendRequest(L"Network.setUserAgentOverride", FormatString(LR"({"userAgent":"%s"})", userAgent->replace(userAgent->find(L"Headless"), 8, L"")));
					return;
				}
			}
			OnStatusChanged("Failed Connection");
		}
		else
		{
			OnStatusChanged("Failed Startup");
		}
	}

	void Close()
	{
		std::scoped_lock lock(devToolsMutex);
		for (const auto& [_, task] : mapQueue) task.set_exception(std::runtime_error("closed"));
		webSocket.close();
		mapMethod.clear();
		mapQueue.clear();
		DWORD exitCode = 0;
		if (GetExitCodeProcess(processInfo.hProcess, &exitCode) && exitCode == STILL_ACTIVE)
		{
			TerminateProcess(processInfo.hProcess, 0);
			WaitForSingleObject(processInfo.hProcess, 100);
			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);
		}
		try { std::filesystem::remove_all(L"devtoolscache"); } catch (std::filesystem::filesystem_error) {}
		OnStatusChanged("Stopped");
	}

	bool Connected()
	{
		std::scoped_lock lock(devToolsMutex);
		return webSocket.state() == QAbstractSocket::ConnectedState;
	}

	JSON::Value<wchar_t> SendRequest(const std::wstring& method, const std::wstring& params)
	{
		if (webSocket.state() != QAbstractSocket::ConnectedState) return {};
		concurrency::task_completion_event<JSON::Value<wchar_t>> response;
		int id = idCounter +=1;
		auto message = FormatString(LR"({"id":%d,"method":"%s","params":%s})", id, method, params);
		{
			std::scoped_lock lock(devToolsMutex);
			mapQueue.try_emplace(id, response);
			webSocket.sendTextMessage(S(message));
			webSocket.flush();
		}
		try { if (auto result = create_task(response).get()[L"result"]) return result; } catch (...) {}
		return {};
	}

	void StartListening(const std::wstring& method)
	{
		std::scoped_lock lock(devToolsMutex);
		mapMethod.try_emplace(method);
	}

	std::vector<JSON::Value<wchar_t>> ListenResults(const std::wstring& method)
	{
		std::scoped_lock lock(devToolsMutex);
		return mapMethod[method];
	}

	void StopListening(const std::wstring& method)
	{
		std::scoped_lock lock(devToolsMutex);
		mapMethod.erase(method);
	}
}

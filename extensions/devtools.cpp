#include "devtools.h"

DevTools::DevTools(QObject* parent) :
	QObject(parent),
	idcounter(0),
	pagenavigated(false),
	translateready(false),
	status("Stopped"),
	session(1)
{	
}

void DevTools::startDevTools(QString path, bool headless, int port)
{
	if (startChrome(path, headless, port))
	{
		QString webSocketDebuggerUrl;
		if (GetwebSocketDebuggerUrl(webSocketDebuggerUrl, port))
		{
			connect(&webSocket, &QWebSocket::stateChanged, this, &DevTools::stateChanged);
			connect(&webSocket, &QWebSocket::textMessageReceived, this, &DevTools::onTextMessageReceived);
			webSocket.open(webSocketDebuggerUrl);
			session += 1;
		}
		else
		{
			status = "Failed to find chrome debug port!";
			emit statusChanged(status);
		}

	}
	else
	{
		status = "Failed to start chrome!";
		emit statusChanged(status);
	}
}

int DevTools::getSession()
{
	return session;
}

QString DevTools::getStatus()
{
	return status;
}

DevTools::~DevTools()
{
	closeDevTools();
}

bool DevTools::startChrome(QString path, bool headless, int port)
{
	if (!std::filesystem::exists(path.toStdWString()))
		return false;
	DWORD exitCode = 0;
	if ((GetExitCodeProcess(processInfo.hProcess, &exitCode) != FALSE) && (exitCode == STILL_ACTIVE))
		return false;
	QString args = "--proxy-server=direct:// --disable-extensions --disable-gpu --user-data-dir=" 
					+ QString::fromStdWString(std::filesystem::current_path())
					+ "\\devtoolscache --remote-debugging-port=" 
					+ QString::number(port);
	if (headless)
		args += " --headless";
	STARTUPINFOW dummy = { sizeof(dummy) };
	if (!CreateProcessW(NULL, (wchar_t*)(path + " " + args).utf16(), nullptr, nullptr, 
		FALSE, 0, nullptr, nullptr, &dummy, &processInfo))
		return false;
	else
		return true;
}

bool DevTools::GetwebSocketDebuggerUrl(QString& url, int port)
{
	url.clear();
	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"127.0.0.1",
		L"POST",
		FormatString(L"/json/list").c_str(),
		"",
		NULL,
		NULL,
		WINHTTP_FLAG_ESCAPE_DISABLE,
		NULL,
		NULL,
		DWORD(port)
		})
	{
		QString qtString = QString::fromStdWString(httpRequest.response);
		QJsonDocument doc = QJsonDocument::fromJson(qtString.toUtf8());
		QJsonArray rootObject = doc.array();

		for (const auto obj : rootObject)
			if (obj.toObject().value("type") == "page")
			{
				url.append(obj.toObject().value("webSocketDebuggerUrl").toString());
				break;
			}
		if (!url.isEmpty())
			return true;
		else
			return false;
	}
	else
		return false;

}

void DevTools::stateChanged(QAbstractSocket::SocketState state)
{
	QMetaEnum metaenum = QMetaEnum::fromType<QAbstractSocket::SocketState>();
	status = metaenum.valueToKey(state);
	emit statusChanged(status);
}

void DevTools::setNavigated(bool value)
{
	mutex.lock();
	pagenavigated = value;
	mutex.unlock();
}

bool DevTools::getNavigated()
{
	return pagenavigated;
}

void DevTools::setTranslate(bool value)
{
	mutex.lock();
	translateready = value;
	mutex.unlock();
}

bool DevTools::getTranslate()
{
	return translateready;
}

bool DevTools::SendRequest(QString method, QJsonObject params, QJsonObject& root)
{
	if (!isConnected())
		return false;
	root = QJsonObject();
	QJsonObject json;
	task_completion_event<QJsonObject> response;
	long id = idIncrement();
	json.insert("id", id);
	json.insert("method", method);
	if (!params.isEmpty())
		json.insert("params", params);
	QJsonDocument doc(json);
	QString message(doc.toJson(QJsonDocument::Compact));
	mutex.lock();
	mapqueue.insert(std::make_pair(id, response));
	mutex.unlock();
	webSocket.sendTextMessage(message);
	webSocket.flush();
	try
	{
		root = create_task(response).get();
	}
	catch (const std::exception& ex)
	{
		response.set_exception(ex);
		return false;
	}
	if (!root.isEmpty())
	{
		if (root.contains("error"))
		{
			return false;
		}
		else if (root.contains("result"))
			return true;
		else
			return false;
	}
	else
		return false;
}

long DevTools::idIncrement()
{
	return ++idcounter;
}

bool DevTools::isConnected()
{
	if (webSocket.state() == QAbstractSocket::ConnectedState)
		return true;
	else
		return false;
}

void DevTools::onTextMessageReceived(QString message)
{
	QJsonDocument doc = QJsonDocument::fromJson(message.toUtf8());
	if (doc.isObject())
	{
		QJsonObject root = doc.object();
		if (root.contains("method"))
		{
			if (root.value("method").toString() == "Page.navigatedWithinDocument")
			{
				mutex.lock();
				pagenavigated = true;
				mutex.unlock();
			}
			if (root.value("method").toString() == "DOM.attributeModified")
			{
				if (root.value("params").toObject().value("value") == "lmt__mobile_share_container")
				{
					mutex.lock();
					translateready = true;
					mutex.unlock();
				}
			}
			return;

		}
		if (root.contains("id"))
		{
			long id = root.value("id").toInt();
			MapResponse::iterator request = mapqueue.find(id);
			if (request != mapqueue.end())
			{
				request->second.set(root);
				mutex.lock();
				mapqueue.erase(request);
				mutex.unlock();
			}
			return;
		}
	}	
}

void DevTools::closeDevTools()
{
	if (this->mapqueue.size() > 0)
	{
		MapResponse::iterator iter = this->mapqueue.begin();
		MapResponse::iterator iend = this->mapqueue.end();
		for (; iter != iend; iter++)
		{
			iter->second.set_exception("exception");
		}
	}
	webSocket.close();
	mapqueue.clear();
	idcounter = 0;

	DWORD exitCode = 0;
	if (GetExitCodeProcess(processInfo.hProcess, &exitCode) != FALSE)
	{
		if (exitCode == STILL_ACTIVE)
		{
			TerminateProcess(processInfo.hProcess, 0);
			WaitForSingleObject(processInfo.hProcess, 100);
			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
		try
		{
			std::filesystem::remove_all(L"devtoolscache");
		}
		catch (const std::exception&)
		{

		}
	}
	status = "Stopped";
	emit statusChanged(status);
}

#include <fstream>
#include <QtCore>
#include <QtWebSockets/QWebSocket>
#include <ppltasks.h>
#include "network.h"

using namespace Concurrency;

typedef std::map<long, task_completion_event<QJsonObject>> MapResponse;

class DevTools : public QObject {
	Q_OBJECT
public:
	explicit DevTools(QObject* parent = nullptr);
	~DevTools();

Q_SIGNALS:
	void statusChanged(const QString &);

private Q_SLOTS:
	void stateChanged(QAbstractSocket::SocketState state);
	void onTextMessageReceived(QString message);

public:
	void startDevTools(QString path, bool headless = false, int port = 9222);
	void closeDevTools();
	void setNavigated(bool value);
	bool getNavigated();
	void setTranslate(bool value);
	bool getTranslate();
	int getSession();
	bool SendRequest(QString command, QJsonObject params, QJsonObject& result);
	QString getStatus();

private:
	bool isConnected();
	bool startChrome(QString path, bool headless = false, int port = 9222);
	bool GetwebSocketDebuggerUrl(QString& url, int port = 9222);
	long idIncrement();
	int session;
	QWebSocket webSocket;
	std::mutex mutex;
	MapResponse mapqueue;
	bool pagenavigated;
	bool translateready;
	long idcounter;
	PROCESS_INFORMATION processInfo;
	QString status;
};
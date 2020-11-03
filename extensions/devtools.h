#include <QtCore>
#include <QtWebSockets/QWebSocket>
#include <ppltasks.h>
#include "network.h"

using namespace Concurrency;

typedef std::map<long, task_completion_event<QJsonObject>> MapResponse;
typedef std::map<long, QJsonObject> MapMethod;

class DevTools : public QObject {
	Q_OBJECT
public:
	explicit DevTools(QObject* parent = nullptr);
	~DevTools();

Q_SIGNALS:
	void statusChanged(const QString&);

private Q_SLOTS:
	void stateChanged(QAbstractSocket::SocketState state);
	void onTextMessageReceived(QString message);

public:
	void startDevTools(QString path, bool headless = false, int port = 9222);
	void closeDevTools();
	bool checkMethod(long id);
	int getSession();
	bool SendRequest(QString method, QJsonObject params, QJsonObject& root);
	long methodToReceive(QString method, QJsonObject params = {});
	QString getStatus();
	QString getUserAgent();

private:
	bool isConnected();
	bool startChrome(QString path, bool headless = false, int port = 9222);
	bool GetJsonfromHTTP(QJsonDocument& doc, QString object, int port = 9222);
	long idIncrement();
	long idmIncrement();
	bool compareJson(QJsonValue stored, QJsonValue params);
	int session;
	QWebSocket webSocket;
	std::mutex mutex;
	MapResponse mapQueue;
	MapMethod mapMethod;
	long idCounter;
	long idMethod;
	PROCESS_INFORMATION processInfo;
	QString status;
	QString userAgent;
};
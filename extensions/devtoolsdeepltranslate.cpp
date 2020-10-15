#include "qtcommon.h"
#include "extension.h"
#include "network.h"
#include "devtools.h"

extern const wchar_t* TRANSLATION_ERROR;
extern Synchronized<std::wstring> translateTo;

bool useCache = true, autostartchrome = false, headlesschrome = true;
int maxSentenceSize = 500, chromeport = 9222;

const char* TRANSLATION_PROVIDER = "DevTools DeepL Translate";
const wchar_t* ERROR_CHROME = L"Error: chrome not started";
const wchar_t* ERROR_START_CHROME = L"Error: failed to start chrome or to connect to it";
const wchar_t* ERROR_GOT_TIMEOUT = L"Error: timeout (s)";
const wchar_t* ERROR_COMMAND_FAIL = L"Error: command failed";
const wchar_t* ERROR_LANGUAGE = L"Error: target languages do not match";
const wchar_t* ERROR_NOTE = L"Error: notification";

QString URL = "https://www.deepl.com/en/translator";
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

int docfound = -1, targetNodeId = -1, session = -1, pageenabled = -1;

std::pair<bool, std::wstring> Translate(const std::wstring& text, DevTools* devtools)
{
	QString qtext = S(text);

	// Check text for repeated symbols (e.g. only ellipsis)
	if (qtext.length() > 2)
		for (int i = 1; i < (qtext.length() - 1); i++)
		{
			if (qtext[i] != qtext[1])
				break;
			if ((i + 2) == qtext.length() && (qtext.front() == qtext.back()))
			{
				return { true, text };
			}
		}

	if (devtools->getStatus() == "Stopped")
	{
		return { false, FormatString(L"%s", ERROR_CHROME) };
	}
	if ((devtools->getStatus().startsWith("Fail")) || (devtools->getStatus().startsWith("Unconnected")))
	{
		return { false, FormatString(L"%s", ERROR_START_CHROME) };
	}
	if (session != devtools->getSession())
	{
		session = devtools->getSession();
		docfound = -1;
		targetNodeId = -1;
		pageenabled = -1;
	}

	// Add spaces near ellipsis for better translation and check for quotes
	qtext.replace(QRegularExpression("[" + QString(8230) + "]" + "[" + QString(8230) + "]" + "[" + QString(8230) + "]"), QString(8230));
	qtext.replace(QRegularExpression("[" + QString(8230) + "]" + "[" + QString(8230) + "]"), QString(8230));
	qtext.replace(QRegularExpression("[" + QString(8230) + "]"), " " + QString(8230) + " ");
	bool checkquote = false;
	if ((qtext.front() == QString(12300)) && (qtext.back() == QString(12301)))
	{
		checkquote = true;
		qtext.remove(0, 1);
		qtext.chop(1);
	}
	QJsonObject root;

	// Enable page feedback
	if (pageenabled == -1)
	{
		if (!devtools->SendRequest("Page.enable", {}, root))
		{
			return { false, FormatString(L"%s", ERROR_COMMAND_FAIL) };
		}
		pageenabled = 1;
	}
	long navigate = devtools->methodToReceive("Page.navigatedWithinDocument");
	long target = devtools->methodToReceive("DOM.attributeModified", { { "value" , "lmt__mobile_share_container" } });

	// Navigate to site
	QString fullurl = URL + "#ja/" + S(translateTo.Copy()) + "/" + qtext;
	if (devtools->SendRequest("Page.navigate", { {"url", fullurl} }, root))
	{
		// Wait until page is loaded
		float timer = 0;
		int timer_stop = 10;
		while (!devtools->checkMethod(navigate) && timer < timer_stop)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			timer += 0.1;
		}
		if (timer >= timer_stop)
		{
			return { false, FormatString(L"%s: %d ", ERROR_GOT_TIMEOUT, timer_stop) };
		}

		// Get document
		if (docfound == -1)
		{
			if (!devtools->SendRequest("DOM.getDocument", {}, root))
			{
				docfound = -1;
				return { false, FormatString(L"%s", ERROR_COMMAND_FAIL) };
			}
			docfound = root.value("result").toObject().value("root").toObject().value("nodeId").toInt();
		}

		//Get target selector
		if (targetNodeId == -1)
		{
			if (!(devtools->SendRequest("DOM.querySelector", { {"nodeId", docfound}, {"selector", "textarea.lmt__target_textarea"} }, root))
				|| (root.value("result").toObject().value("nodeId").toInt() == 0))
			{
				docfound = -1;
				return { false, FormatString(L"%s", ERROR_COMMAND_FAIL) };
			}
			targetNodeId = root.value("result").toObject().value("nodeId").toInt();
		}

		// Wait for translation to appear on the web page
		timer = 0;
		while (!devtools->checkMethod(target) && timer < timer_stop)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			timer += 0.1;
		}
		
		// Catch the translation
		devtools->SendRequest("DOM.getOuterHTML", { {"nodeId", targetNodeId + 1} }, root);
		QString OuterHTML = root.value("result").toObject().value("outerHTML").toString();
		if (OuterHTML == "<div></div>")
		{
			// Try to catch the notification
			int noteNodeId = -1;
			if (!(devtools->SendRequest("DOM.querySelector", { {"nodeId", docfound}, {"selector", "div.lmt__system_notification"} }, root))
				|| (root.value("result").toObject().value("nodeId").toInt() == 0))
			{
				return { false, FormatString(L"%s: %d ", ERROR_GOT_TIMEOUT, timer_stop) };
			}
			noteNodeId = root.value("result").toObject().value("nodeId").toInt();

			if (devtools->SendRequest("DOM.getOuterHTML", { {"nodeId", noteNodeId} }, root))
			{
				OuterHTML = root.value("result").toObject().value("outerHTML").toString();
			}
			OuterHTML.remove(QRegExp("<[^>]*>"));
			OuterHTML = OuterHTML.trimmed();

			return { false, FormatString(L"%s: %s", ERROR_NOTE, S(OuterHTML)) };
		}
		OuterHTML.remove(QRegExp("<[^>]*>"));
		OuterHTML = OuterHTML.trimmed();

		// Check if the translator output language does not match the selected language
		if (devtools->SendRequest("DOM.getAttributes", { {"nodeId", targetNodeId} }, root))
		{
			QJsonObject result = root.value("result").toObject();
			QJsonArray attributes = result.value("attributes").toArray();
			for (size_t i = 0; i < attributes.size(); i++)
			{
				if (attributes[i].toString() == "lang")
				{
					QString targetlang = attributes[i + 1].toString().mid(0, 2);
					if (targetlang != S(translateTo.Copy()))
					{
						return { false, FormatString(L"%s (%s): %s", ERROR_LANGUAGE, S(targetlang), S(OuterHTML)) };
					}
				}
			}
		}

		// Get quotes back
		if (checkquote)
		{
			OuterHTML = "\"" + OuterHTML + "\"";
		}
		return { true, S(OuterHTML) };
	}
	else
	{
		return { false, FormatString(L"%s", ERROR_COMMAND_FAIL) };
	}
}
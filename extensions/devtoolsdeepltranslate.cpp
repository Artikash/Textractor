#include "qtcommon.h"
#include "extension.h"
#include "devtools.h"

extern const wchar_t* TRANSLATION_ERROR;
extern Synchronized<std::wstring> translateTo, translateFrom;

bool useCache = true, autoStartChrome = false, headlessChrome = true;
int maxSentenceSize = 500, chromePort = 9222;

const char* TRANSLATION_PROVIDER = "DevTools DeepL Translate";
const wchar_t* ERROR_CHROME = L"Error: Chrome not started";
const wchar_t* ERROR_START_CHROME = L"Error: failed to start Chrome or to connect to it";
const wchar_t* ERROR_GOT_TIMEOUT = L"Error: timeout (s)";
const wchar_t* ERROR_COMMAND_FAIL = L"Error: command failed";
const wchar_t* ERROR_LANGUAGE = L"Error: target languages do not match";
const wchar_t* ERROR_NOTE = L"Error: notification";
const wchar_t* ERROR_EMPTY_ANSWER = L"Error: empty translation";

QString URL = "https://www.deepl.com/en/translator";
QStringList languagesTo
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

QStringList languagesFrom
{
	"Any language: ",
	"Chinese: zh",
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

int docFound = -1, targetNodeId = -1, session = -1, pageEnabled = -1, userAgentFlag = -1, backup = -1, sourceLangId = -1, mobileShareId = -1;
long update = -1, callNumber = 0;
std::vector<long> callQueue;

std::pair<bool, std::wstring> Translate(const std::wstring& text, DevTools* devTools)
{
	QString qtext = S(text);
	qtext.remove(QString(12288)); // japanese space (no need for translator)
	qtext.replace(QString(12289), ","); // replace the japanese comma with the latin comma for correct translation

	// Remove quotes
	bool checkQuote = false;
	if ((qtext.front() == QString(12300) && qtext.back() == QString(12301)) // japanese quotation marks
		|| (qtext.front() == "\"" && qtext.back() == "\""))
	{
		checkQuote = true;
		qtext.remove(0, 1);
		qtext.chop(1);
	}

	// Check specific cases (sentence has only one japanese symbol or consists of ellipsis)
	int count = qtext.count(QString(8230)); // ellipsis
	if (count == qtext.length()
		|| (count == (qtext.length() - 1) && qtext.back() == QString(12290))) // japanese end of a sentence
	{
		return { true, text };
	}
	if (count == (qtext.length() - 1)) 
	{
		qtext.remove(QString(8230));
		qtext += QString(12290) + QString(8230); // add the end symbol for correct translation
	}

	// Put quotes back
	if (checkQuote)
	{
		qtext = "\"" + qtext + "\"";
	}

	// Check status
	if (devTools->getStatus() == "Stopped")
	{
		return { false, FormatString(L"%s", ERROR_CHROME) };
	}
	if (devTools->getStatus().startsWith("Fail") || devTools->getStatus().startsWith("Unconnected"))
	{
		return { false, FormatString(L"%s", ERROR_START_CHROME) };
	}
	if (session != devTools->getSession())
	{
		session = devTools->getSession();
		docFound = -1;
		targetNodeId = -1;
		sourceLangId = -1;
		mobileShareId = -1;
		pageEnabled = -1;
		userAgentFlag = -1;
		update = -1;
		callNumber = 0;
		backup = -1;
	}

	// Remove tags and reduce the number of ellipsis for correct translation
	qtext.remove(QRegExp("<[^>]*>"));
	qtext.replace(QRegExp("(" + QString(8230) + ")+"), " " + QString(8230));

	// Enable page feedback
	QJsonObject root;
	int errorCode = 0;
	if (pageEnabled == -1)
	{
		if (!devTools->SendRequest("Page.enable", {}, root))
			errorCode = 1;
		else
			pageEnabled = 1;
	}

	// Change user-agent if in headless mode
	if (userAgentFlag == -1 && errorCode == 0)
	{
		QString userAgent = devTools->getUserAgent();
		if (!userAgent.isEmpty())
		{
			userAgent.replace("HeadlessChrome", "Chrome");
			if (!devTools->SendRequest("Network.setUserAgentOverride", { {"userAgent", userAgent} }, root))
				errorCode = 1;
			else
				userAgentFlag = 1;
		}
	}

	// Increase queue counter and wait until previous calls are done
	float timer = 0;
	int timerStop = 10;
	long callTag = ++callNumber;
	callQueue.insert(callQueue.begin(), callTag);
	while (errorCode == 0 && callQueue.back() != callTag && timer < 2 * timerStop)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		timer += 0.1;
	}
	if (timer >= 2 * timerStop)
		errorCode = 5;

	// Set methods to receive
	long navigate = devTools->methodToReceive("Page.navigatedWithinDocument");
	long target;
	if (mobileShareId != -1 && backup == -1)
		target = devTools->methodToReceive("DOM.attributeModified", { { "nodeId" , mobileShareId } , { "value" , "lmt__mobile_share_container lmt--mobile-hidden" } });
	else if (mobileShareId == -1 && backup == -1)
		target = devTools->methodToReceive("DOM.attributeModified", { { "value" , "lmt__mobile_share_container lmt--mobile-hidden" } });
	else
		target = devTools->methodToReceive("DOM.childNodeCountUpdated");
	if (update == -1)
		update = devTools->methodToReceive("DOM.documentUpdated");

	// Navigate to site and wait until it is loaded
	QString checkFrom = translateFrom.Copy().empty() ? "ja" : S(translateFrom.Copy());
	QString fullUrl = URL + "#" + checkFrom + "/" + S(translateTo.Copy()) + "/" + qtext;
	if (errorCode == 0 && !devTools->SendRequest("Page.navigate", { {"url", fullUrl} }, root))
		errorCode = 1;
	timer = 0;
	while (errorCode == 0 && !devTools->checkMethod(navigate) && timer < timerStop)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		timer += 0.1;
	}
	if (timer >= timerStop)
		errorCode = 2;

	// Check if document is outdated
	if (devTools->checkMethod(update))
	{
		docFound = -1;
		targetNodeId = -1;
		update = -1;
	}

	// Get document
	if (docFound == -1 && errorCode == 0)
	{
		if (!devTools->SendRequest("DOM.getDocument", {}, root))
			errorCode = 1;
		else
			docFound = root.value("result").toObject().value("root").toObject().value("nodeId").toInt();
	}

	// Get target selector
	if (targetNodeId == -1 && errorCode == 0)
	{
		if (!devTools->SendRequest("DOM.querySelector", { {"nodeId", docFound}, {"selector", "textarea.lmt__target_textarea"} }, root)
			|| root.value("result").toObject().value("nodeId").toInt() == 0)
		{
			docFound = -1;
			errorCode = 1;
		}
		else
			targetNodeId = root.value("result").toObject().value("nodeId").toInt();
	}

	// Get source language selector
	if (sourceLangId == -1 && errorCode == 0)
	{
		if (!devTools->SendRequest("DOM.querySelector", { {"nodeId", docFound}, {"selector", "div.lmt__language_select--source"} }, root)
			|| root.value("result").toObject().value("nodeId").toInt() == 0)
		{
			docFound = -1;
			errorCode = 1;
		}
		else
			sourceLangId = root.value("result").toObject().value("nodeId").toInt();
	}

	// Get mobile share selector
	if (mobileShareId == -1 && errorCode == 0)
	{
		if (!devTools->SendRequest("DOM.querySelector", { {"nodeId", docFound}, {"selector", "div.lmt__mobile_share_container"} }, root)
			|| root.value("result").toObject().value("nodeId").toInt() == 0)
		{
			docFound = -1;
			errorCode = 1;
		}
		else
			mobileShareId = root.value("result").toObject().value("nodeId").toInt();
	}

	// Wait for the translation to appear on the web page
	timer = 0;
	while (errorCode == 0 && !devTools->checkMethod(target) && timer < timerStop)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		timer += 0.1;
	}

	// Catch the translation
	QString OuterHTML;
	if (errorCode == 0)
	{
		if (!devTools->SendRequest("DOM.getOuterHTML", { {"nodeId", targetNodeId + 1} }, root))
		{
			targetNodeId = -1;
			errorCode = 1;
		}
		else
		{
			OuterHTML = root.value("result").toObject().value("outerHTML").toString();
		}
	}
	if (errorCode == 0 && OuterHTML == "<div></div>")
	{
		// Try to catch the notification
		int noteNodeId = -1;
		if (!devTools->SendRequest("DOM.querySelector", { {"nodeId", docFound}, {"selector", "div.lmt__system_notification"} }, root)
			|| root.value("result").toObject().value("nodeId").toInt() == 0)
		{
			if (timer >= timerStop)
				errorCode = 2;
			else
				errorCode = 6;
		}
		else
		{
			noteNodeId = root.value("result").toObject().value("nodeId").toInt();
			if (errorCode == 0 && devTools->SendRequest("DOM.getOuterHTML", { {"nodeId", noteNodeId} }, root))
			{
				OuterHTML = root.value("result").toObject().value("outerHTML").toString();
			}
			errorCode = 3;
		}
	}
	OuterHTML.remove(QRegExp("<[^>]*>"));
	OuterHTML = OuterHTML.trimmed();
	if (backup == -1 && errorCode == 0 && timer >= timerStop)
		backup = 1;

	// Check if the translator output language does not match the selected language
	QString targetLang;
	if (errorCode == 0 && devTools->SendRequest("DOM.getAttributes", { {"nodeId", targetNodeId} }, root))
	{
		QJsonArray attributes = root.value("result").toObject().value("attributes").toArray();
		for (size_t i = 0; i < attributes.size(); i++)
		{
			if (attributes[i].toString() == "lang")
			{
				targetLang = attributes[i + 1].toString().mid(0, 2);
				if (targetLang != S(translateTo.Copy()))
				{
					errorCode = 4;
				}
			}
			break;
		}
	}

	// Check selected source language
	if (errorCode == 0 && devTools->SendRequest("DOM.getAttributes", { {"nodeId", sourceLangId} }, root))
	{
		QJsonArray attributes = root.value("result").toObject().value("attributes").toArray();
		for (size_t i = 0; i < attributes.size(); i++)
		{
			if (attributes[i].toString() == "dl-selected-lang"
				&& attributes[i + 1].toString().mid(0, 2) != S(translateFrom.Copy()))
			{
				QStringList::const_iterator constIter;
				for (constIter = languagesFrom.constBegin(); constIter != languagesFrom.constEnd(); ++constIter)
				{
					if (constIter->contains(": " + S(translateFrom.Copy())))
						break;
				}
				devTools->SendRequest("Runtime.evaluate", { {"expression",
					"document\
					.querySelector('div.lmt__language_select--source')\
					.querySelector('button.lmt__language_select__active')\
					.click();\
					document\
					.evaluate(\"//button[contains(text(), '"
						+ constIter->split(": ")[0] + "')]\", \
						document.querySelector('div.lmt__language_select__menu'),\
						null, XPathResult.FIRST_ORDERED_NODE_TYPE, null)\
					.singleNodeValue\
					.click();"
				} }, root);
			}
		}
	}

	callQueue.pop_back();
	if (errorCode == 0)
		return { true, S(OuterHTML) };
	else if (errorCode == 1)
		return { false, FormatString(L"%s", ERROR_COMMAND_FAIL) };
	else if (errorCode == 2)
		return { false, FormatString(L"%s: %d", ERROR_GOT_TIMEOUT, timerStop) };
	else if (errorCode == 3)
		return { false, FormatString(L"%s: %s", ERROR_NOTE, S(OuterHTML)) };
	else if (errorCode == 4)
		return { false, FormatString(L"%s (%s): %s", ERROR_LANGUAGE, S(targetLang), S(OuterHTML)) };
	else if (errorCode == 5)
		return { false, FormatString(L"%s: %d", ERROR_GOT_TIMEOUT, 2*timerStop) };
	else if (errorCode == 6)
		return { false, FormatString(L"%s", ERROR_EMPTY_ANSWER) };
	else
		return { false, FormatString(L"%s", TRANSLATION_ERROR) };
}
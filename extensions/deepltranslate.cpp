#include "qtcommon.h"
#include "extension.h"
#include "network.h"
#include <random>

extern const wchar_t* TRANSLATION_ERROR;
extern const char* USE_PREV_SENTENCE_CONTEXT;

extern QSettings settings;
extern QFormLayout* display;
extern Synchronized<std::wstring> translateTo;

const char* TRANSLATION_PROVIDER = "DeepL Translate";
QStringList languages
{
	"Chinese: ZH",
	"Dutch: NL",
	"English: EN",
	"French: FR",
	"German: DE",
	"Italian: IT",
	"Japanese: JA",
	"Polish: PL",
	"Portuguese: PT",
	"Russian: RU",
	"Spanish: ES",
};

const wchar_t* accept[] = { L"*/*", nullptr };

Synchronized<std::wstring> LMTBID;

bool useContext = true;
Synchronized<std::unordered_map<int64_t, std::wstring>> context;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		auto checkbox = new QCheckBox;
		checkbox->setChecked(useContext);
		display->addRow(USE_PREV_SENTENCE_CONTEXT, checkbox);
		QObject::connect(checkbox, &QCheckBox::clicked, [](bool checked) { settings.setValue(USE_PREV_SENTENCE_CONTEXT, useContext = checked); });
	}
	break;
	case DLL_PROCESS_DETACH:
	{
	}
	break;
	}
	return TRUE;
}

std::pair<bool, std::wstring> Translate(const std::wstring& text, SentenceInfo sentenceInfo)
{
	// the following code was reverse engineered from the DeepL website; it's as close as I could make it but I'm not sure what parts of this could be removed and still have it work
	int64_t r = _time64(nullptr), n = std::count(text.begin(), text.end(), L'i') + 1LL;
	static std::atomic<int> id = 10000 * std::uniform_int_distribution(0, 9999)(std::mt19937(std::random_device()()));
	std::string jsonText;
	for (auto ch : WideStringToString(text))
		if (ch == '"') jsonText += "\\\"";
		else jsonText += ch;
	// user_preferred_langs? what should preferred_num_beans and priority be? does timestamp do anything? other translation quality options?
	auto body = FormatString(R"(
{
	"id": %d,
	"jsonrpc": "2.0",
	"method": "LMT_handle_jobs",
	"params": {
		"priority": -1,
		"timestamp": %lld,
		"lang": {
			"source_lang_user_selected": "auto",
			"target_lang": "%s"
		},
		"jobs": [{
			"kind": "default",
			"preferred_num_beams": 4,
			"quality": "fast",
			"raw_en_context_after": [],
			"raw_en_sentence": "%s",
			"raw_en_context_before": [%s]
		}]
	}
}
	)", ++id, r + (n - r % n), WideStringToString(translateTo->c_str()), jsonText, useContext ? WideStringToString(context->operator[](sentenceInfo["text number"])) : "");
	context->insert_or_assign(sentenceInfo["text number"], L'"' + text + L'"');
	std::wstring headers = L"Host: www2.deepl.com\r\nAccept-Language: en-US,en;q=0.5\r\nContent-type: text/plain\r\nOrigin: https://www.deepl.com\r\nTE: Trailers"
		+ LMTBID.Acquire().contents;
	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"www2.deepl.com",
		L"POST",
		L"/jsonrpc",
		WINHTTP_FLAG_SECURE,
		NULL,
		L"https://www.deepl.com/translator",
		accept,
		headers.c_str(),
		body.data(),
		body.size()
	})
	{
		auto LMTBID = httpRequest.headers.find(L"LMTBID="), end = httpRequest.headers.find(L';', LMTBID); // not sure if this cookie does anything
		if (LMTBID != std::wstring::npos && end != std::wstring::npos) ::LMTBID->assign(L"\r\nCookie: " + httpRequest.headers.substr(LMTBID, end - LMTBID));
		// Response formatted as JSON: translation starts with preprocessed_sentence":" and ends with ","
		if (std::wsmatch results; std::regex_search(httpRequest.response, results, std::wregex(L"postprocessed_sentence\":\"(.+?)\",\""))) return { true, results[1] };
		else return { false, FormatString(L"%s: %s", TRANSLATION_ERROR, httpRequest.response) };
	}
	else return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

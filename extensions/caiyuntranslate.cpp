#include "qtcommon.h"
#include "translatewrapper.h"
#include "network.h"

extern const wchar_t* TRANSLATION_ERROR;

const char* TRANSLATION_PROVIDER = "Caiyun Translate";
const char* GET_API_KEY_FROM = "https://dashboard.caiyunapp.com/";
extern const QStringList languagesTo
{
	"Chinese",
	"English",
	"Japanese",
},
languagesFrom
{
	"AutoDetect",
	"Chinese",
	"English",
	"Japanese",
};

extern const std::unordered_map<std::wstring, std::unordered_map<std::wstring,std::wstring>> codes
{
	{  L"Chinese" , {
		{ L"English" , L"zh2en" },
		{ L"Japanese",L"zh2ja" } 
		}
	},
	{  L"English" , {
		{ L"Chinese" , L"en2zh" },
		{ L"Japanese",L"en2ja" } 
		}
	},
	{  L"Japanese" , {
		{ L"English" , L"ja2en" },
		{ L"Chinese",L"ja2zh" } 
		}
	},
	{  L"AutoDetect" , {
		{ L"English" , L"auto2en" },
		{ L"Japanese",L"auto2ja" },
		{L"Chinese",L"auto2zh"}
		}
	},
};

bool translateSelectedOnly = true, useRateLimiter = true, rateLimitSelected = true, useCache = true, useFilter = true;
int tokenCount = 30, rateLimitTimespan = 60000, maxSentenceSize = 1000;

enum KeyType { CAT, REST };
int keyType = REST;

std::pair<bool, std::wstring> Translate(const std::wstring& text, TranslationParam tlp)
{
	if (tlp.authKey.empty())
		tlp.authKey=L"3975l6lr5pcbvidl6jl2";
	std::wstring transcode=codes.at(tlp.translateFrom).at(tlp.translateTo);
	std::string body=FormatString("{\"source\":[\"%s\"],\"trans_type\":\"%S\",\"request_id\":\"demo\"}", JSON::Escape(WideStringToString(text)), transcode);
	std::wstring headers = L"Content-Type: application/json\r\nX-Authorization: token " + tlp.authKey;
	if (HttpRequest httpRequest{
		L"Mozilla/5.0 Textractor",
		L"api.interpreter.caiyunai.com",
		L"POST",
		L"/v1/translator",
		body,
		headers.c_str()
	})
		if (httpRequest.response.find(L"target")!=std::wstring::npos) 
			return { true, Copy(JSON::Parse(httpRequest.response)[L"target"][0].String()).value() };
		else 
			return { false, FormatString(L"%s: %s,%s,%s", TRANSLATION_ERROR, httpRequest.response,transcode,headers) };
	else 
		return { false, FormatString(L"%s (code=%u)", TRANSLATION_ERROR, httpRequest.errorCode) };
}

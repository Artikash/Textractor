#include <Windows.h>
#include <string>

typedef std::wstring (*ExtensionFunction)(std::wstring, DWORD64);
void LoadExtensions();
std::wstring DispatchSentenceToExtensions(std::wstring sentence, DWORD64 info);
#include <Windows.h>

typedef void(*ExtensionFunction)(LPCWSTR, DWORD64);
void LoadExtensions();
void DispatchSentenceToExtensions(LPCWSTR sentence, DWORD64 info);
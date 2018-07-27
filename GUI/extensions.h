#ifndef EXTENSIONS_H
#define EXTENSIONS_H

#include <Windows.h>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>

std::map<int, std::wstring> LoadExtensions();
std::wstring DispatchSentenceToExtensions(std::wstring sentence, std::unordered_map<std::string, int> miscInfo);

typedef std::wstring(*ExtensionFunction)(std::wstring, std::unordered_map<std::string, int>&);

#endif // EXTENSIONS_H

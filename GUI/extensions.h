#ifndef EXTENSIONS_H
#define EXTENSIONS_H

#include <Windows.h>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <QComboBox>

std::map<int, QString> LoadExtensions();
std::wstring DispatchSentenceToExtensions(std::wstring sentence, std::unordered_map<std::string, int> miscInfo);

typedef void(*ExtensionFunction)(std::wstring&, std::unordered_map<std::string, int>&);
extern QComboBox* ttCombo;

#endif // EXTENSIONS_H

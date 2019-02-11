#include "common.h"
#include <filesystem>

int main()
{
	wchar_t path[MAX_PATH] = {};
	GetModuleFileNameW(NULL, path, MAX_PATH);
	*(wcsrchr(path, L'\\') + 1) = 0;
	for (auto file : std::filesystem::directory_iterator(path))
		if (file.path().extension() == L".dll") LoadLibraryW(file.path().c_str());
	Sleep(10000);
}

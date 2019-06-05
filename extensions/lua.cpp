#include "extension.h"
#include "util.h"
#include <fstream>
#include <QMainWindow>
#include <QLayout>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTimer>

extern const char* LUA_INTRO;
extern const char* LOAD_LUA_SCRIPT;
extern const wchar_t* LUA_ERROR;

constexpr auto LUA_SAVE_FILE = u8"Textractor.lua";

extern "C" // Lua library
{
	enum LuaType { LUA_TNIL, LUA_TBOOLEAN, LUA_TLIGHTUSERDATA, LUA_TNUMBER, LUA_TSTRING, LUA_TTABLE, LUA_TFUNCTION, LUA_TUSERDATA, LUA_TTHREAD };

	enum LuaStatus { LUA_OK, LUA_YIELD, LUA_ERRRUN, LUA_ERRSYNTAX, LUA_ERRMEM, LUA_ERRGCMM, LUA_ERRERR };

	struct lua_State;
	lua_State* luaL_newstate();
	void luaL_openlibs(lua_State*);
	void lua_close(lua_State*);
	LuaStatus luaL_loadstring(lua_State*, const char* str);

	const char* lua_tolstring(lua_State*, int index, size_t* size);
	const char* lua_pushstring(lua_State*, const char* str);
	void lua_pushinteger(lua_State*, int64_t n);
	void lua_createtable(lua_State*, int narr, int nrec);
	void lua_settable(lua_State*, int index);

	void lua_settop(lua_State*, int index);
	LuaType lua_getglobal(lua_State*, const char* name);
	LuaStatus lua_pcallk(lua_State*, int nargs, int nresults, int msgh, void*, void*);
}

bool luaL_dostring(lua_State* L, const char* str)
{
	return luaL_loadstring(L, str) || lua_pcallk(L, 0, -1, 0, NULL, NULL);
}

bool logErrors = true;
Synchronized<std::string> script;
std::atomic<int> revCount = 0;

struct : QMainWindow
{
	void launch()
	{
		auto centralWidget = new QWidget(this);
		auto layout = new QHBoxLayout(centralWidget);
		auto scriptEditor = new QPlainTextEdit(std::string(std::istreambuf_iterator<char>(std::ifstream(LUA_SAVE_FILE, std::ios::in)), {}).c_str(), centralWidget);
		auto loadButton = new QPushButton(LOAD_LUA_SCRIPT, centralWidget);
		if (scriptEditor->toPlainText().isEmpty()) scriptEditor->setPlainText(LUA_INTRO);
		layout->addWidget(scriptEditor);
		layout->addWidget(loadButton);
		save = [=]
		{
			auto script = scriptEditor->toPlainText().toUtf8();
			std::ofstream(LUA_SAVE_FILE, std::ios::out | std::ios::trunc).write(script, strlen(script));
		};
		connect(loadButton, &QPushButton::clicked, [=](bool)
		{
			revCount += 1;
			script->assign(scriptEditor->toPlainText().toUtf8());
			save();
		});
		resize(800, 600);
		setCentralWidget(centralWidget);
		setWindowTitle("Lua");
		show();
	}

	std::function<void()> save;
}*window = nullptr;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		QTimer::singleShot(0, []
		{
			(window = new std::remove_pointer_t<decltype(window)>)->launch();
		});
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		if (window) window->save();
		if (lpReserved == NULL) // https://blogs.msdn.microsoft.com/oldnewthing/20120105-00/?p=8683
		{
			delete window;
		}
	}
	break;
	}
	return TRUE;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	thread_local static struct { std::unique_ptr<lua_State, Functor<lua_close>> L{ luaL_newstate() }; operator lua_State*() { return L.get(); } } L;
	thread_local static auto _ = (luaL_openlibs(L), luaL_dostring(L, "function ProcessSentence() end"));
	thread_local static int revCount = 0;

	if (::revCount > revCount)
	{
		revCount = ::revCount;
		luaL_dostring(L, "ProcessSentence = nil");
		if (luaL_dostring(L, script->c_str()) != LUA_OK)
		{
			sentence += L"\n" + FormatWideString(LUA_ERROR, StringToWideString(lua_tolstring(L, 1, nullptr)).c_str());
			lua_settop(L, 0);
			return logErrors;
		}
	}

	if (lua_getglobal(L, "ProcessSentence") != LUA_TFUNCTION)
	{
		sentence += L"\n" + FormatWideString(LUA_ERROR, L"ProcessSentence is not a function");
		lua_settop(L, 0);
		return logErrors;
	}
	lua_pushstring(L, WideStringToString(sentence).c_str());
	lua_createtable(L, 0, 0);
	for (auto info = sentenceInfo.infoArray; info->name != nullptr; ++info)
	{
		lua_pushstring(L, info->name);
		lua_pushinteger(L, info->value);
		lua_settable(L, 3);
	}
	if (lua_pcallk(L, 2, 1, 0, NULL, NULL) != LUA_OK)
	{
		sentence += L"\n" + FormatWideString(LUA_ERROR, StringToWideString(lua_tolstring(L, 1, nullptr)).c_str());
		lua_settop(L, 0);
		return logErrors;
	}
	if (const char* newSentence = lua_tolstring(L, 1, nullptr))
	{
		sentence = StringToWideString(newSentence);
		lua_settop(L, 0);
		return true;
	}
	lua_settop(L, 0);
	return false;
}

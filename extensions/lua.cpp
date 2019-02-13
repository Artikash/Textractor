#include "extension.h"
#include "util.h"
#include "text.h"
#include "defs.h"
#include <QMainWindow>
#include <QLayout>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTimer>

extern "C"
{
	enum LuaType
	{
		LUA_TNONE = -1,
		LUA_TNIL = 0,
		LUA_TBOOLEAN = 1,
		LUA_TLIGHTUSERDATA = 2,
		LUA_TNUMBER = 3,
		LUA_TSTRING = 4,
		LUA_TTABLE = 5,
		LUA_TFUNCTION = 6,
		LUA_TUSERDATA = 7,
		LUA_TTHREAD = 8
	};

	enum LuaStatus
	{
		LUA_OK = 0,
		LUA_YIELD = 1,
		LUA_ERRRUN = 2,
		LUA_ERRSYNTAX = 3,
		LUA_ERRMEM = 4,
		LUA_ERRGCMM = 5,
		LUA_ERRERR = 6
	};

	struct lua_State;
	__declspec(dllimport) lua_State* luaL_newstate();
	__declspec(dllimport) void luaL_openlibs(lua_State*);
	__declspec(dllimport) void lua_close(lua_State*);

	__declspec(dllimport) LuaStatus luaL_loadstring(lua_State*, const char* str);

	__declspec(dllimport) LuaStatus lua_pcallk(lua_State*, int nargs, int nresults, int msgh, void*, void*);

	__declspec(dllimport) const char* lua_tolstring(lua_State*, int index, size_t* size);
	__declspec(dllimport) const char* lua_pushstring(lua_State*, const char* str);

	__declspec(dllimport) void lua_pushinteger(lua_State*, int64_t n);

	__declspec(dllimport) void lua_createtable(lua_State*, int narr, int nrec);
	__declspec(dllimport) void lua_settable(lua_State*, int index);

	__declspec(dllimport) void lua_settop(lua_State*, int index);
	__declspec(dllimport) LuaType lua_getglobal(lua_State*, const char* name);
}

bool luaL_dostring(lua_State* L, const char* str)
{
	return luaL_loadstring(L, str) || lua_pcallk(L, 0, -1, 0, NULL, NULL);
}

bool logErrors = true;

std::mutex m;
std::string script;
int revCount = 0;

struct : QMainWindow
{
	void launch()
	{
		auto centralWidget = new QWidget(this);
		auto layout = new QVBoxLayout(centralWidget);
		auto scriptEditor = new QPlainTextEdit(centralWidget);
		auto loadButton = new QPushButton("Load Script", centralWidget);
		layout->addWidget(scriptEditor);
		layout->addWidget(loadButton);
		connect(loadButton, &QPushButton::clicked, [=](bool)
		{
			std::lock_guard l(m);
			++revCount;
			script = scriptEditor->toPlainText().toUtf8();
		});
		resize(800, 600);
		setCentralWidget(centralWidget);
		setWindowTitle("Lua");
		show();
	}
}*window = nullptr;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		QTimer::singleShot(0, []
		{
			std::lock_guard l(m);
			(window = new std::remove_pointer_t<decltype(window)>)->launch();
		});
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		if (lpReserved == NULL) // https://blogs.msdn.microsoft.com/oldnewthing/20120105-00/?p=8683
		{
			std::lock_guard l(m);
			delete window;
			window = nullptr;
		}
	}
	break;
	}
	return TRUE;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	thread_local static std::unique_ptr<lua_State, Functor<lua_close>> L_(luaL_newstate());
	thread_local static lua_State* L = L_.get();
	thread_local static auto _ = (luaL_openlibs(L), luaL_dostring(L, "function ProcessSentence() end"));
	thread_local static int revCount = 0;

	if (::revCount > revCount)
	{
		std::lock_guard l(m);
		revCount = ::revCount;
		luaL_dostring(L, "ProcessSentence = nil");
		if (luaL_dostring(L, script.c_str()) != LUA_OK)
		{
			sentence += NEWLINE + LUA_ERROR + StringToWideString(lua_tolstring(L, -1, nullptr));
			lua_settop(L, 0);
			return logErrors;
		}
	}

	if (lua_getglobal(L, "ProcessSentence") != LUA_TFUNCTION)
	{
		sentence += NEWLINE + LUA_ERROR + L"ProcessSentence is not a function";
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
		sentence += NEWLINE + LUA_ERROR + StringToWideString(lua_tolstring(L, -1, nullptr));
		lua_settop(L, 0);
		return logErrors;
	}
	if (const char* newSentence = lua_tolstring(L, -1, nullptr))
	{
		sentence = StringToWideString(newSentence);
		lua_settop(L, 0);
		return true;
	}
	lua_settop(L, 0);
	return false;
}

#include "qtcommon.h"
#include "extension.h"
#include <fstream>
#include <QPlainTextEdit>

extern const char* LUA_INTRO;
extern const char* LOAD_SCRIPT;
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

class Window : public QDialog
{
public:
	Window()
		: QDialog(nullptr, Qt::WindowMinMaxButtonsHint)
	{
		Localize();
		connect(&loadButton, &QPushButton::clicked, this, &Window::LoadScript);

		if (scriptEditor.toPlainText().isEmpty()) scriptEditor.setPlainText(LUA_INTRO);
		layout.addWidget(&scriptEditor);
		layout.addWidget(&loadButton);

		resize(800, 600);
		setWindowTitle("Lua");
		QMetaObject::invokeMethod(this, &QWidget::show, Qt::QueuedConnection);

		LoadScript();
	}

	~Window()
	{
		Save();
	}

private:
	void LoadScript()
	{
		revCount += 1;
		script->assign(scriptEditor.toPlainText().toUtf8());
		Save();
	}

	void Save()
	{
		QTextFile(LUA_SAVE_FILE, QIODevice::WriteOnly | QIODevice::Truncate).write(scriptEditor.toPlainText().toUtf8());
	}

	QHBoxLayout layout{ this };
	QPlainTextEdit scriptEditor{ QTextFile(LUA_SAVE_FILE, QIODevice::ReadOnly).readAll(), this };
	QPushButton loadButton{ LOAD_SCRIPT, this };
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	thread_local struct { std::unique_ptr<lua_State, Functor<lua_close>> L{ luaL_newstate() }; operator lua_State*() { return L.get(); } } L;
	thread_local auto _ = (luaL_openlibs(L), luaL_dostring(L, "function ProcessSentence() end"));
	thread_local int revCount = 0;

	if (::revCount > revCount)
	{
		revCount = ::revCount;
		luaL_dostring(L, "ProcessSentence = nil");
		if (luaL_dostring(L, script.Copy().c_str()) != LUA_OK)
		{
			sentence += L"\n" + FormatString(LUA_ERROR, StringToWideString(lua_tolstring(L, 1, nullptr)));
			lua_settop(L, 0);
			return logErrors;
		}
	}

	if (lua_getglobal(L, "ProcessSentence") != LUA_TFUNCTION)
	{
		sentence += L"\n" + FormatString(LUA_ERROR, L"ProcessSentence is not a function");
		lua_settop(L, 0);
		return logErrors;
	}
	lua_pushstring(L, WideStringToString(sentence).c_str());
	lua_createtable(L, 0, 0);
	for (auto info = sentenceInfo.infoArray; info->name; ++info)
	{
		lua_pushstring(L, info->name);
		lua_pushinteger(L, info->value);
		lua_settable(L, 3);
	}
	if (lua_pcallk(L, 2, 1, 0, NULL, NULL) != LUA_OK)
	{
		sentence += L"\n" + FormatString(LUA_ERROR, StringToWideString(lua_tolstring(L, 1, nullptr)));
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

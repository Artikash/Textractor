#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <deque>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <algorithm>
#include <regex>
#include <memory>
#include <optional>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <cstdint>
#include <cassert>

#ifdef _WIN64
constexpr bool x64 = true;
#else
constexpr bool x64 = false;
#endif

#define MESSAGE(text) MessageBoxW(NULL, text, L"Textractor", MB_OK)
#define CRITIAL_SECTION static std::mutex m; std::scoped_lock l(m)

template <typename T> using Array = T[];

template<typename T, typename M = std::mutex>
class Synchronized
{
public:
	template <typename... Args>
	Synchronized(Args&&... args) : contents(std::forward<Args>(args)...) {}

	struct Locker
	{
		T* operator->() { return &contents; }
		std::unique_lock<M> lock;
		T& contents;
	};

	Locker Acquire() { return { std::unique_lock(m), contents }; }
	Locker operator->() { return Acquire(); }

private:
	T contents;
	M m;
};

template <auto F>
struct Functor
{
	template <typename... Args>
	auto operator()(Args&&... args) const { return std::invoke(F, std::forward<Args>(args)...); }
};

template <typename HandleCloser = Functor<CloseHandle>>
class AutoHandle
{
public:
	AutoHandle(HANDLE h) : h(h) {}
	operator HANDLE() { return h.get(); }
	PHANDLE operator&() { static_assert(sizeof(*this) == sizeof(HANDLE)); return (PHANDLE)this; }
	operator bool() { return h.get() != NULL && h.get() != INVALID_HANDLE_VALUE; }

private:
	struct HandleCleaner { void operator()(void* h) { if (h != INVALID_HANDLE_VALUE) HandleCloser()(h); } };
	std::unique_ptr<void, HandleCleaner> h;
};

static struct
{
	BYTE DUMMY[100];
	template <typename T> 
	operator T*() { static_assert(sizeof(T) < sizeof(DUMMY)); return (T*)DUMMY; }
} DUMMY;

template <typename T>
inline auto FormatArg(T arg) { return arg; }

template <typename C>
inline auto FormatArg(const std::basic_string<C>& arg) { return arg.c_str(); }

#pragma warning(push)
#pragma warning(disable: 4996)
template <typename... Args>
inline std::string FormatString(const char* format, const Args&... args)
{
	std::string buffer(snprintf(nullptr, 0, format, FormatArg(args)...), '\0');
	sprintf(buffer.data(), format, FormatArg(args)...);
	return buffer;
}

template <typename... Args>
inline std::wstring FormatString(const wchar_t* format, const Args&... args)
{
	std::wstring buffer(_snwprintf(nullptr, 0, format, FormatArg(args)...), L'\0');
	_swprintf(buffer.data(), format, FormatArg(args)...);
	return buffer;
}
#pragma warning(pop)

#ifdef _DEBUG
#define TEST(...) static auto _ = CreateThread(nullptr, 0, [](auto) { __VA_ARGS__; return 0UL; }, NULL, 0, nullptr); 
#else
#define TEST(...)
#endif

#ifdef _DEBUG
#define TEST_SYNC(...) static auto _ = [] { __VA_ARGS__; return 0UL; }(); 
#else
#define TEST_SYNC(...)
#endif

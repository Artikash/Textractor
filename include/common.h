#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
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

template <typename T> using Array = T[];

template<typename E, typename M = std::mutex>
class ThreadSafe
{
public:
	template <typename... Args>
	ThreadSafe(Args&&... args) : contents(std::forward<Args>(args)...) {}
	auto operator->()
	{
		struct
		{
			E* operator->() { return ptr; }
			std::unique_lock<M> lock;
			E* ptr;
		} lockedProxy{ std::unique_lock(mtx), &contents };
		return lockedProxy;
	}

private:
	E contents;
	M mtx;
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

#pragma warning(push)
#pragma warning(disable: 4996)
template <typename... Args>
inline std::string FormatString(const char* format, Args... args)
{
	std::string buffer(snprintf(nullptr, 0, format, args...), '\0');
	sprintf(buffer.data(), format, args...);
	return buffer;
}

template <typename... Args>
inline std::wstring FormatWideString(const wchar_t* format, Args... args)
{
	std::wstring buffer(_snwprintf(nullptr, 0, format, args...), L'\0');
	_swprintf(buffer.data(), format, args...);
	return buffer;
}
#pragma warning(pop)

#ifdef _DEBUG
#define TEST(...) inline auto TEST_RUNNER_DUMMY = CreateThread(nullptr, 0, [](auto) { __VA_ARGS__; return 0UL; }, NULL, 0, nullptr); 
#else
#define TEST(...)
#endif

#ifdef _DEBUG
#define TEST_SYNC(...) inline auto TEST_RUNNER_DUMMY = [] { __VA_ARGS__; return 0UL; }(); 
#else
#define TEST_SYNC(...)
#endif

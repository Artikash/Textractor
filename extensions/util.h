#pragma once

#include "common.h"

class RateLimiter
{
public:
	RateLimiter(int requests, int delay) : requestsLeft(requests), delay(delay) {}
	bool Request() { CreateTimerQueueTimer(&DUMMY, timerQueue, [](void* This, BOOLEAN) { ((RateLimiter*)This)->requestsLeft += 1; }, this, delay, 0, 0); return --requestsLeft > 0; }
	int delay;

private:
	inline static HANDLE DUMMY;
	std::atomic<int> requestsLeft;
	AutoHandle<Functor<DeleteTimerQueue>> timerQueue = CreateTimerQueue();
};

inline std::wstring StringToWideString(const std::string& text)
{
	std::vector<wchar_t> buffer(text.size() + 1);
	MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, buffer.data(), buffer.size());
	return buffer.data();
}

inline std::string WideStringToString(const std::wstring& text)
{
	std::vector<char> buffer((text.size() + 1) * 4);
	WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, buffer.data(), buffer.size(), nullptr, nullptr);
	return buffer.data();
}

// textthread.cc
// 8/24/2013 jichi
// Branch IHF/TextThread.cpp, rev 133

#include "textthread.h"
#include "host.h"
#include "const.h"

TextThread::TextThread(ThreadParam tp, HookParam hp, std::wstring name) : handle(threadCounter++), name(name), tp(tp), hp(hp) {}

TextThread::~TextThread()
{
	SetEvent(deletionEvent);
	flushThread.join();
	CloseHandle(deletionEvent);
}

std::wstring TextThread::GetStorage()
{
	LOCK(threadMutex);
	return storage;
}

void TextThread::AddSentence(std::wstring sentence)
{
	// Dispatch to extensions occurs here. Don't hold mutex! Extensions might take a while!
	if (Output(this, sentence))
	{
		LOCK(threadMutex);
		storage += sentence;
	}
}

void TextThread::Push(const BYTE* data, int len)
{
	if (len < 0) return;
	LOCK(threadMutex);
	buffer += hp.type & USING_UNICODE
		? std::wstring((wchar_t*)data, len / 2)
		: StringToWideString(std::string((char*)data, len), hp.codepage != 0 ? hp.codepage : defaultCodepage);
	if (std::all_of(buffer.begin(), buffer.end(), [&](wchar_t c) { return repeatingChars.count(c) > 0; })) buffer.clear();
	lastPushTime = GetTickCount();
}

void TextThread::Flush()
{
	std::unique_lock locker(threadMutex);
	if (buffer.empty()) return;
	if (buffer.size() > maxBufferSize || GetTickCount() - lastPushTime > flushDelay)
	{
		std::wstring sentence = buffer;
		buffer.clear();

		locker.unlock(); // This algorithm might take a while
		std::unordered_set<wchar_t> repeatingChars;
		for (std::wsmatch results; std::regex_search(sentence, results, std::wregex(L"([^\\x00]{6,})\\1\\1")); sentence = results[1])
			repeatingChars = std::unordered_set(sentence.begin(), sentence.end());
		locker.lock();

		this->repeatingChars = repeatingChars;

		locker.unlock();
		AddSentence(sentence);
	}
}

// EOF

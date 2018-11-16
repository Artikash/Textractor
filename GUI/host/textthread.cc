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

bool TextThread::FilterRepetition(std::wstring& sentence)
{
	wchar_t* end = sentence.data() + sentence.size();
	for (int len = sentence.size() / 3; len > 6; --len)
		if (wcsncmp(end - len * 3, end - len * 2, len) == 0 && wcsncmp(end - len * 3, end - len * 1, len) == 0)
			return true | FilterRepetition(sentence = end - len);
	return false;
}

void TextThread::Flush()
{
	std::unique_lock locker(threadMutex);
	if (buffer.empty()) return;
	if (buffer.size() > maxBufferSize || GetTickCount() - lastPushTime > flushDelay)
	{
		std::wstring sentence = buffer;
		buffer.clear();

		if (FilterRepetition(sentence)) repeatingChars = std::unordered_set(sentence.begin(), sentence.end());
		else repeatingChars.clear();

		locker.unlock();
		AddSentence(sentence);
	}
}

// EOF

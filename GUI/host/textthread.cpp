#include "textthread.h"
#include "const.h"
#include "text.h"
#include "host.h"
#include "util.h"

TextThread::TextThread(ThreadParam tp, HookParam hp, std::wstring name) : handle(threadCounter++), name(name), tp(tp), hp(hp) 
{
	OnCreate(this);
}

TextThread::~TextThread()
{
	SetEvent(deletionEvent);
	flushThread.join();
	OnDestroy(this);
}

std::wstring TextThread::GetStorage()
{
	return storage->c_str();
}

void TextThread::Start()
{
	deletionEvent = CreateEventW(nullptr, FALSE, FALSE, NULL);
	flushThread = std::thread([&] { while (WaitForSingleObject(deletionEvent, 10) == WAIT_TIMEOUT) Flush(); });
}

void TextThread::AddSentence(std::wstring sentence)
{
	if (Output(this, sentence)) storage->append(sentence);
}

void TextThread::Push(const BYTE* data, int len)
{
	if (!flushThread.joinable() || len < 0) return;
	LOCK(bufferMutex);
	if (hp.type & USING_UNICODE) buffer += std::wstring((wchar_t*)data, len / 2);
	else if (auto converted = Util::StringToWideString(std::string((char*)data, len), hp.codepage ? hp.codepage : defaultCodepage)) buffer += converted.value();
	else Host::AddConsoleOutput(INVALID_CODEPAGE);
	if (std::all_of(buffer.begin(), buffer.end(), [&](wchar_t c) { return repeatingChars.count(c) > 0; })) buffer.clear();
	lastPushTime = GetTickCount();
}

void TextThread::Flush()
{
	std::wstring sentence;
	{
		LOCK(bufferMutex);
		if (buffer.empty()) return;
		if (buffer.size() < maxBufferSize && GetTickCount() - lastPushTime < flushDelay) return;
		sentence = buffer;
		buffer.clear();

		if (Util::RemoveRepetition(sentence)) repeatingChars = std::unordered_set(sentence.begin(), sentence.end());
		else repeatingChars.clear();
	}
	AddSentence(sentence);
}

#include "textthread.h"
#include "const.h"
#include "text.h"
#include "host.h"
#include "util.h"

TextThread::TextThread(ThreadParam tp, HookParam hp, std::optional<std::wstring> name) :
	handle(threadCounter++),
	name(name.value_or(Util::StringToWideString(hp.name).value())),
	tp(tp),
	hp(hp)
{
	CreateTimerQueueTimer(timer, NULL, [](void* This, BOOLEAN) { ((TextThread*)This)->Flush(); }, this, 25, 25, WT_EXECUTELONGFUNCTION);
	OnCreate(this);
}

TextThread::~TextThread()
{
	OnDestroy(this);
}

void TextThread::Push(const BYTE* data, int len)
{
	if (len < 0) return;
	LOCK(bufferMutex);
	if (hp.type & USING_UNICODE) buffer += std::wstring((wchar_t*)data, len / 2);
	else if (auto converted = Util::StringToWideString(std::string((char*)data, len), hp.codepage ? hp.codepage : defaultCodepage)) buffer += converted.value();
	else Host::AddConsoleOutput(INVALID_CODEPAGE);
	if (std::all_of(buffer.begin(), buffer.end(), [&](wchar_t c) { return repeatingChars.count(c) > 0; })) buffer.clear();
	lastPushTime = GetTickCount();
}

void TextThread::PushSentence(std::wstring sentence)
{
	LOCK(bufferMutex);
	buffer += sentence;
	lastPushTime = 0;
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
	if (Output(this, sentence)) storage->append(sentence);
}

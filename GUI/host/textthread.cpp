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
	CreateTimerQueueTimer(timer, NULL, Flush, this, 25, 25, WT_EXECUTELONGFUNCTION);
	OnCreate(this);
}

TextThread::~TextThread()
{
	OnDestroy(this);
}

std::wstring TextThread::GetStorage()
{
	return storage->c_str();
}

void TextThread::AddSentence(std::wstring sentence)
{
	if (Output(this, sentence)) storage->append(sentence);
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

void CALLBACK Flush(void* thread, BOOLEAN)
{
	auto This = (TextThread*)thread;
	std::wstring sentence;
	{
		LOCK(This->bufferMutex);
		if (This->buffer.empty()) return;
		if (This->buffer.size() < This->maxBufferSize && GetTickCount() - This->lastPushTime < This->flushDelay) return;
		sentence = This->buffer;
		This->buffer.clear();

		if (Util::RemoveRepetition(sentence)) This->repeatingChars = std::unordered_set(sentence.begin(), sentence.end());
		else This->repeatingChars.clear();
	}
	This->AddSentence(sentence);
}

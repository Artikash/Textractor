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
{}

void TextThread::Start()
{
	CreateTimerQueueTimer(&timer, NULL, [](void* This, BOOLEAN) { ((TextThread*)This)->Flush(); }, this, 10, 10, WT_EXECUTELONGFUNCTION);
}

void TextThread::Stop()
{
	timer = NULL;
}

void TextThread::AddSentence(const std::wstring& sentence)
{
	queuedSentences->push_back(sentence);
}

void TextThread::Push(const BYTE* data, int len)
{
	if (len < 0) return;
	std::scoped_lock lock(bufferMutex);

	BYTE doubleByteChar[2];
	if (len == 1) // doublebyte characters must be processed as pairs
		if (leadByte) std::tie(doubleByteChar[0], doubleByteChar[1], data, len, leadByte) = std::tuple(leadByte, data[0], doubleByteChar, 2, 0 );
		else if (IsDBCSLeadByteEx(hp.codepage ? hp.codepage : Host::defaultCodepage, data[0])) std::tie(leadByte, len) = std::tuple(data[0], 0);

	if (hp.type & USING_UNICODE) buffer += std::wstring((wchar_t*)data, len / 2);
	else if (auto converted = Util::StringToWideString(std::string((char*)data, len), hp.codepage ? hp.codepage : Host::defaultCodepage)) buffer += converted.value();
	else Host::AddConsoleOutput(INVALID_CODEPAGE);
	lastPushTime = GetTickCount();

	if (std::all_of(buffer.begin(), buffer.end(), [&](wchar_t c) { return repeatingChars.count(c) > 0; })) buffer.clear();
	if (filterRepetition && Util::RemoveRepetition(buffer)) // sentence repetition detected, which means the entire sentence has already been received
	{
		repeatingChars = std::unordered_set(buffer.begin(), buffer.end());
		AddSentence(buffer);
		buffer.clear();
	}
}

void TextThread::Flush()
{
	std::vector<std::wstring> sentences;
	queuedSentences->swap(sentences);
	for (auto& sentence : sentences)
		if (Output(*this, sentence)) storage->append(sentence);

	std::scoped_lock lock(bufferMutex);
	if (buffer.empty()) return;
	if (buffer.size() > maxBufferSize || GetTickCount() - lastPushTime > flushDelay)
	{
		AddSentence(buffer);
		buffer.clear();
	}
}

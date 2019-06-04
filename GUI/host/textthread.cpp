#include "textthread.h"
#include "host.h"
#include "util.h"

extern const wchar_t* INVALID_CODEPAGE;

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

void TextThread::AddSentence(std::wstring&& sentence)
{
	queuedSentences->emplace_back(std::move(sentence));
}

void TextThread::Push(BYTE* data, int length)
{
	if (length < 0) return;
	std::scoped_lock lock(bufferMutex);

	BYTE doubleByteChar[2];
	if (length == 1) // doublebyte characters must be processed as pairs
		if (leadByte) std::tie(doubleByteChar[0], doubleByteChar[1], data, length, leadByte) = std::tuple(leadByte, data[0], doubleByteChar, 2, 0);
		else if (IsDBCSLeadByteEx(hp.codepage ? hp.codepage : Host::defaultCodepage, data[0])) std::tie(leadByte, length) = std::tuple(data[0], 0);

	if (hp.type & USING_UNICODE) buffer.append((wchar_t*)data, length / sizeof(wchar_t));
	else if (auto converted = Util::StringToWideString(std::string((char*)data, length), hp.codepage ? hp.codepage : Host::defaultCodepage)) buffer.append(converted.value());
	else Host::AddConsoleOutput(INVALID_CODEPAGE);
	lastPushTime = GetTickCount();
	
	if (filterRepetition)
	{
		if (std::all_of(buffer.begin(), buffer.end(), [&](auto ch) { return repeatingChars.find(ch) != repeatingChars.end(); })) buffer.clear();
		if (Util::RemoveRepetition(buffer)) // sentence repetition detected, which means the entire sentence has already been received
		{
			repeatingChars = std::unordered_set(buffer.begin(), buffer.end());
			AddSentence(std::move(buffer));
			buffer.clear();
		}
	}

	if (flushDelay == 0 && hp.type & USING_STRING)
	{
		AddSentence(std::move(buffer));
		buffer.clear();
	}
}

void TextThread::Flush()
{
	if (storage->size() > 10'000'000) storage->erase(0, 8'000'000); // https://github.com/Artikash/Textractor/issues/127#issuecomment-486882983

	std::deque<std::wstring> sentences;
	queuedSentences->swap(sentences);
	for (auto& sentence : sentences)
	{
		sentence.erase(std::remove(sentence.begin(), sentence.end(), L'\0'));
		if (Output(*this, sentence)) storage->append(sentence);
	}

	std::scoped_lock lock(bufferMutex);
	if (buffer.empty()) return;
	if (buffer.size() > maxBufferSize || GetTickCount() - lastPushTime > flushDelay)
	{
		AddSentence(std::move(buffer));
		buffer.clear();
	}
}

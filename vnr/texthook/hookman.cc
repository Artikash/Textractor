// hookman.cc
// 8/24/2013 jichi
// Branch IHF/HookManager.cpp, rev 133
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
# pragma warning (disable:4146)   // C4146: unary minus operator applied to unsigned type
#endif // _MSC_VER

#include "hookman.h"
#include "vnrhook/include/const.h"
#include "vnrhook/include/defs.h"
#include "vnrhook/include/types.h"
#include "winmutex/winmutex.h"
#include <atlbase.h>

#define HM_LOCK CriticalSectionLocker hmLocker(hmCs) // Synchronized scope for accessing private data

HookManager::HookManager() :
	create(nullptr),
	remove(nullptr),
	reset(nullptr),
	attach(nullptr),
	detach(nullptr),
	nextThreadNumber(0),
	textThreadsByParams(),
	processRecordsByIds()
{
	InitializeCriticalSection(&hmCs);

	// Console text thread
	current = textThreadsByParams[{ 0, -1UL, -1UL, -1UL }] = new TextThread({ 0, -1UL, -1UL, -1UL }, nextThreadNumber++, splitDelay);
	current->Status() |= USING_UNICODE | CURRENT_SELECT;
}

HookManager::~HookManager()
{
	HM_LOCK;
	DeleteCriticalSection(&hmCs);
}

TextThread *HookManager::FindSingle(DWORD number)
{
	HM_LOCK;
	for (auto i : textThreadsByParams)
		if (i.second->Number() == number) 
			return i.second;
	return nullptr;
}

void HookManager::SetCurrent(TextThread *it)
{
	HM_LOCK;
	if (it == nullptr) return;
	current->Status() &= ~CURRENT_SELECT;
	current = it;
	it->Status() |= CURRENT_SELECT;
}

void HookManager::SelectCurrent(DWORD num)
{
	HM_LOCK;
	if (TextThread *st = FindSingle(num)) 
	{
		SetCurrent(st);
		if (reset) reset(st);
	}
}

void HookManager::RemoveSingleHook(DWORD pid, DWORD addr)
{
	HM_LOCK;
	std::vector<ThreadParameter> removedThreads;
	for (auto i : textThreadsByParams)
		if (i.first.pid == pid && i.first.hook == addr)
		{
			if (remove) remove(i.second);
			delete i.second;
			removedThreads.push_back(i.first);
		}
	for (auto i : removedThreads) textThreadsByParams.erase(i);
	SelectCurrent(0);
}

void HookManager::RemoveProcessContext(DWORD pid)
{
	HM_LOCK;
	std::vector<ThreadParameter> removedThreads;
	for (auto i : textThreadsByParams)
		if (i.first.pid == pid)
		{
			if (remove) remove(i.second);
			delete i.second;
			removedThreads.push_back(i.first);
		}
	for (auto i : removedThreads) textThreadsByParams.erase(i);
	SelectCurrent(0);
}

void HookManager::RegisterProcess(DWORD pid, HANDLE hostPipe)
{
	HM_LOCK;
	ProcessRecord* record = processRecordsByIds[pid] = new ProcessRecord;
	record->hostPipe = hostPipe;
	record->hookman_section = OpenFileMappingW(FILE_MAP_READ, FALSE, (ITH_SECTION_ + std::to_wstring(pid)).c_str());
	record->hookman_map = MapViewOfFile(record->hookman_section, FILE_MAP_READ, 0, 0, HOOK_SECTION_SIZE / 2); // jichi 1/16/2015: Changed to half to hook section size
	record->process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	record->hookman_mutex = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, (ITH_HOOKMAN_MUTEX_ + std::to_wstring(pid)).c_str());
	if (attach) attach(pid);
}

void HookManager::UnRegisterProcess(DWORD pid)
{
	HM_LOCK;
	ProcessRecord pr = *processRecordsByIds[pid];
	CloseHandle(pr.hookman_mutex);
	UnmapViewOfFile(pr.hookman_map);
	CloseHandle(pr.process_handle);
	CloseHandle(pr.hookman_section);
	processRecordsByIds.erase(pid);
	RemoveProcessContext(pid);
	if (detach) detach(pid);
}

void HookManager::DispatchText(DWORD pid, DWORD hook, DWORD retn, DWORD spl, const BYTE *text, int len)
{
	// jichi 20/27/2013: When PID is zero, the text comes from console, which I don't need
	if (!text || !pid || len <= 0)
		return;
	HM_LOCK;
	ThreadParameter tp = { pid, hook, retn, spl };
	TextThread *it;
	if ((it = textThreadsByParams[tp]) == nullptr)
	{
		it = textThreadsByParams[tp] = new TextThread(tp, nextThreadNumber++, splitDelay);
		if (create) create(it);
	}
	it->AddText(text, len);
}

void HookManager::AddConsoleOutput(LPCWSTR text)
{
	HM_LOCK;
	int len = wcslen(text) * 2;
	TextThread *console = textThreadsByParams[{ 0, -1UL, -1UL, -1UL }];
	console->AddSentence(std::wstring(text));
}

void HookManager::ClearCurrent()
{
	HM_LOCK;
	current->Reset();
	if (reset) reset(current);
}

ProcessRecord *HookManager::GetProcessRecord(DWORD pid)
{
	HM_LOCK;
	return processRecordsByIds[pid];
}

HANDLE HookManager::GetHostPipe(DWORD pid)
{
	HM_LOCK;
	return processRecordsByIds[pid] ? processRecordsByIds[pid]->hostPipe : nullptr;
}

HookParam HookManager::GetHookParam(DWORD pid, DWORD addr)
{
	HM_LOCK;
	HookParam ret = {};
	ProcessRecord* pr = GetProcessRecord(pid);
	if (pr == nullptr) return ret;
	MutexLocker locker(pr->hookman_mutex);
	const Hook* hooks = (const Hook*)pr->hookman_map;
	for (int i = 0; i < MAX_HOOK; ++i)
		if (hooks[i].Address() == addr)
			ret = hooks[i].hp;
	return ret;
}

std::wstring HookManager::GetHookName(DWORD pid, DWORD addr)
{
	HM_LOCK;
	std::string buffer;
	ProcessRecord* pr = GetProcessRecord(pid);
	if (pr == nullptr) return L"";
	MutexLocker locker(pr->hookman_mutex);
	USES_CONVERSION;
	const Hook* hooks = (const Hook*)pr->hookman_map;
	for (int i = 0; i < MAX_HOOK; ++i)
	{
		if (hooks[i].Address() == addr)
		{
			buffer.resize(hooks[i].NameLength());
			ReadProcessMemory(pr->process_handle, hooks[i].Name(), &buffer[0], hooks[i].NameLength(), nullptr);
		}
	}
	return std::wstring(A2W(buffer.c_str()));
}

// EOF

// texthook.cc
// 8/24/2013 jichi
// Branch: ITH_DLL/texthook.cpp, rev 128
// 8/24/2013 TODO: Clean up this file

#ifdef _MSC_VER
# pragma warning (disable:4100)   // C4100: unreference formal parameter
# pragma warning (disable:4018)   // C4018: sign/unsigned mismatch
//# pragma warning (disable:4733)   // C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
#endif // _MSC_VER

#include "../main.h"
#include "texthook.h"
#include "include/const.h"
//#include "winseh/winseh.h"

//#define ConsoleOutput(...)   (void)0    // jichi 9/17/2013: I don't need this ><

// - Global variables -

// 10/14/2014 jichi: disable GDI hooks
static bool gdi_hook_enabled_ = true; // enable GDI by default
static bool gdiplus_hook_enabled_ = false; // disable GDIPlus by default
bool GDIHooksEnabled() { return ::gdi_hook_enabled_; }
bool GDIPlusHooksEnabled() { return ::gdiplus_hook_enabled_; }
void EnableGDIHooks() { ::gdi_hook_enabled_ = true; }
void EnableGDIPlusHooks() { ::gdiplus_hook_enabled_ = true; }
void DisableGDIHooks() { ::gdi_hook_enabled_ = false; }
void DisableGDIPlusHooks() { ::gdiplus_hook_enabled_ = false; }

//FilterRange filter[8];

DWORD flag,
      enter_count;

TextHook *hookman,
         *current_available;

// - TextHook methods -

// jichi 12/2/2013: This function mostly return 0.
// It return the hook address only for auxiliary case.
// However, because no known hooks are auxiliary, this function always return 0.
//
// jichi 5/11/2014:
// - dwDataBase: the stack address
// - dwRetn: the return address of the hook


int TextHook::InsertHook()
{
  int ok = 1;
  //ConsoleOutput("vnrcli:InsertHook: enter");
  WaitForSingleObject(hmMutex, 0);
  if (hp.type & DIRECT_READ) ok = InsertReadCode();
  else
  {
	  ConsoleOutput("only /R (read) codes supported in 64 bit");
  }
  ReleaseMutex(hmMutex);
  //ConsoleOutput("vnrcli:InsertHook: leave");
  return ok;
}

DWORD WINAPI ReaderThread(LPVOID threadParam)
{
	TextHook* hook = (TextHook*)threadParam;
	BYTE buffer[PIPE_BUFFER_SIZE] = {};
	char testChar = 0;
	unsigned int changeCount = 0;
	const char* currentAddress = (char*)hook->hp.address;
	while (true)
	{
		Sleep(50);
		if (testChar == *currentAddress)
		{
			changeCount = 0;
			continue;
		}
		testChar = *currentAddress;
		if (++changeCount > 10)
		{
			ConsoleOutput("NextHooker: memory constantly changing, useless to read");
			ConsoleOutput("NextHooker: remove read code");
			break;
		}

		int dataLen;
		if (hook->hp.type & USING_UNICODE)
			dataLen = wcslen((const wchar_t*)currentAddress) * 2;
		else
			dataLen = strlen(currentAddress);

		*(DWORD*)buffer = hook->hp.address;
		*(DWORD*)(buffer + 4) = 0;
		*(DWORD*)(buffer + 8) = 0;
		memcpy(buffer + HEADER_SIZE, currentAddress, dataLen);
		DWORD unused;
		WriteFile(::hookPipe, buffer, dataLen + HEADER_SIZE, &unused, nullptr);

		if (hook->hp.offset == 0) continue;
		currentAddress += dataLen + hook->hp.offset;
		testChar = *currentAddress;
	}
	hook->ClearHook();
	return 0;
}

int TextHook::InsertReadCode()
{
	hp.hook_len = 0x40;
	//Check if the new hook range conflict with existing ones. Clear older if conflict.
	TextHook *it = hookman;
	for (int i = 0; i < currentHook; it++) {
		if (it->Address())
			i++;
		if (it == this)
			continue;
		if ((it->Address() >= hp.address && it->Address() < hp.hook_len + hp.address) || (it->Address() <= hp.address && it->Address() + it->Length() > hp.address)) 
			it->ClearHook();
	}
	//if (!IthGetMemoryRange((LPCVOID)hp.address, 0, 0))
	//{
	//	ConsoleOutput("cannot access read address");
	//	return no;
	//}
	hp.readerHandle = CreateThread(nullptr, 0, ReaderThread, this, 0, nullptr);
	return yes;
	
}

int TextHook::InitHook(const HookParam &h, LPCSTR name, WORD set_flag)
{
  WaitForSingleObject(hmMutex, 0);
  hp = h;
  hp.type |= set_flag;
  if (name && name != hook_name) {
	  SetHookName(name);
  }
  currentHook++;
  current_available = this+1;
  while (current_available->Address())
    current_available++;
  ReleaseMutex(hmMutex);
  return 1;
}

int TextHook::RemoveReadCode()
{
	if (!hp.address) return no;
	TerminateThread(hp.readerHandle, 0);
	CloseHandle(hp.readerHandle);
	return yes;
}

int TextHook::ClearHook()
{
  int err;
  WaitForSingleObject(hmMutex, 0);
  ConsoleOutput("vnrcli:RemoveHook: enter");
  err = RemoveReadCode();
  NotifyHookRemove(hp.address);
  if (hook_name) {
    delete[] hook_name;
    hook_name = nullptr;
  }
  memset(this, 0, sizeof(TextHook)); // jichi 11/30/2013: This is the original code of ITH
  //if (current_available>this)
  //  current_available = this;
  currentHook--;
  ConsoleOutput("vnrcli:RemoveHook: leave");
  ReleaseMutex(hmMutex);
  return err;
}

int TextHook::SetHookName(LPCSTR name)
{
  name_length = strlen(name) + 1;
  if (hook_name)
    delete[] hook_name;
  hook_name = new char[name_length];
  //ITH_MEMSET_HEAP(hook_name, 0, sizeof(wchar_t) * name_length); // jichi 9/26/2013: zero memory
  strcpy(hook_name, name);
  return 0;
}

// EOF

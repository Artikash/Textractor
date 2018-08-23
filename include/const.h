#pragma once

// vnrhook/const.h
// 8/23/2013 jichi
// Branch: ITH/common.h, rev 128

enum { MESSAGE_SIZE = 500, PIPE_BUFFER_SIZE = 0x1000 };

// jichi 375/2014: Add offset of pusha/pushad
// http://faydoc.tripod.com/cpu/pushad.htm
// http://agth.wikia.com/wiki/Cheat_Engine_AGTH_Tutorial
//
// Warning: The offset in ITH has -4 offset comparing to pusha and AGTH
enum pusha_off 
{
	pusha_eax_off = -0x4,
	pusha_ecx_off = -0x8,
	pusha_edx_off = -0xc,
	pusha_ebx_off = -0x10,
	pusha_esp_off = -0x14,
	pusha_ebp_off = -0x18,
	pusha_esi_off = -0x1c,
	pusha_edi_off = -0x20,
	pusha_off = -0x24 // pushad offset
};

enum HostCommandType 
{
	HOST_COMMAND = -1, // null type
	HOST_COMMAND_NEW_HOOK = 0,
	HOST_COMMAND_REMOVE_HOOK = 1,
	HOST_COMMAND_MODIFY_HOOK = 2,
	HOST_COMMAND_HIJACK_PROCESS = 3,
	HOST_COMMAND_DETACH = 4
};

enum HostNotificationType 
{
	HOST_NOTIFICATION = -1, // null type
	HOST_NOTIFICATION_TEXT = 0,
	HOST_NOTIFICATION_NEWHOOK = 1,
	HOST_NOTIFICATION_RMVHOOK = 2
};

enum HookParamType : unsigned long 
{
	USING_STRING = 0x1, // type(data) is char* or wchar_t* and has length
	USING_UNICODE = 0x2, // type(data) is wchar_t or wchar_t*
	BIG_ENDIAN = 0x4, // type(data) is char
	DATA_INDIRECT = 0x8,
	USING_SPLIT = 0x10, // aware of split time?
	SPLIT_INDIRECT = 0x20,
	MODULE_OFFSET = 0x40, // do hash module, and the address is relative to module
	//FUNCTION_OFFSET   = 0x80,    // do hash function, and the address is relative to funccion
	USING_UTF8 = 0x100,
	NO_CONTEXT = 0x400,
	HOOK_EMPTY = 0x800,
	FIXING_SPLIT = 0x1000,
	DIRECT_READ = 0x2000, // /R read code instead of classic /H hook code
	HOOK_ENGINE = 0x4000,
	HOOK_ADDITIONAL = 0x8000
};

enum { FIXED_SPLIT_VALUE = 0x10001 }; // 6/1/2014: Fixed split value for hok parameter. Fuse all threads, and prevent floating

#pragma once

// texthook/const.h
// 8/23/2013 jichi
// Branch: ITH/common.h, rev 128

enum Misc { MESSAGE_SIZE = 500, PIPE_BUFFER_SIZE = 2000, SHIFT_JIS = 932, MAX_MODULE_SIZE = 120, HOOK_NAME_SIZE = 30, FIXED_SPLIT_VALUE = 0x10001 };

enum HostCommandType { HOST_COMMAND_NEW_HOOK, HOST_COMMAND_REMOVE_HOOK, HOST_COMMAND_FIND_HOOK, HOST_COMMAND_MODIFY_HOOK, HOST_COMMAND_HIJACK_PROCESS, HOST_COMMAND_DETACH };

enum HostNotificationType { HOST_NOTIFICATION_TEXT, HOST_NOTIFICATION_NEWHOOK, HOST_NOTIFICATION_FOUND_HOOK, HOST_NOTIFICATION_RMVHOOK };

enum HookParamType : unsigned
{
	USING_STRING = 0x1, // type(data) is char* or wchar_t* and has length
	USING_UNICODE = 0x2, // type(data) is wchar_t or wchar_t*
	BIG_ENDIAN = 0x4, // type(data) is char
	DATA_INDIRECT = 0x8,
	USING_SPLIT = 0x10, // use ctx2 or not
	SPLIT_INDIRECT = 0x20,
	MODULE_OFFSET = 0x40, // address is relative to module
	FUNCTION_OFFSET = 0x80, // address is relative to function
	USING_UTF8 = 0x100,
	READ_SEARCH = 0x200, // unspecified address: search for text instead
	NO_CONTEXT = 0x400,
	HOOK_EMPTY = 0x800,
	FIXING_SPLIT = 0x1000,
	DIRECT_READ = 0x2000, // /R read code instead of classic /H hook code
	HOOK_ENGINE = 0x4000,
	HOOK_ADDITIONAL = 0x8000
};

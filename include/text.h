#pragma once

constexpr auto SELECT_PROCESS = u8"Select Process";
constexpr auto ATTACH_INFO = u8"If you don't see the process you want to attach, try running with admin rights\r\n"
"You can also type in the process id";
constexpr auto ADD_HOOK = u8"Add hook";
constexpr auto CODE_INFODUMP = u8"Enter hook code\r\n"
"/H{A|B|W|S|Q|V}[N][codepage#]data_offset[*deref_offset1][:split_offset[*deref_offset2]]@addr[:module[:func]]\r\n"
"OR\r\n"
"Enter read code\r\n"
"/R{S|Q|V}[codepage#][*deref_offset|0]@addr\r\n"
"All numbers except codepage in hexadecimal\r\n"
"A/B: Shift-JIS char little/big endian\r\n"
"W: UTF-16 char\r\n"
"S/Q/V: Shift-JIS/UTF-16/UTF-8 string\r\n"
"Negatives for data_offset/sub_offset refer to registers\r\n"
"-4 for EAX, -8 for ECX, -C for EDX, -10 for EBX, -14 for ESP, -18 for EBP, -1C for ESI, -20 for EDI\r\n"
"* means dereference pointer+deref_offset";
constexpr auto UNHOOK = u8"Unhook";
constexpr auto REMOVE_HOOK = u8"Which hook to remove?";
constexpr auto SELECT_EXTENSION = u8"Select Extension";
constexpr auto EXTENSIONS = u8"Extensions (*.dll)";
constexpr auto ABOUT = L"Textractor beta v3.5.0 (project homepage: https://github.com/Artikash/Textractor)\r\n"
"Made with love by Artikash (email: akashmozumdar@gmail.com)\r\n"
"Please contact Artikash with any problems, feature requests, or questions relating to Textractor\r\n"
"You can do so via the project homepage (issues section) or via email\r\n"
"Source code available under GPLv3 at project homepage";
constexpr auto TOO_MANY_THREADS = L"Textractor: too many text threads: can't create more";
constexpr auto ALREADY_INJECTED = L"Textractor: already injected";
constexpr auto ARCHITECTURE_MISMATCH = L"Textractor: architecture mismatch: try 32 bit Textractor instead";
constexpr auto INJECT_FAILED = L"Textractor: couldn't inject";
constexpr auto INVALID_CODE = L"Textractor: invalid code";
constexpr auto NO_HOOKS = L"Textractor: no hooks detected";
constexpr auto INVALID_CODEPAGE = L"Textractor: couldn't convert text (invalid codepage?)";
constexpr auto PIPE_CONNECTED = u8"Textractor: pipe connected";
constexpr auto DISABLE_HOOKS = u8"Textractor: hooks don't work on x64, only read codes work: engine disabled";
constexpr auto INSERTING_HOOK = u8"Textractor: inserting hook: %s";
constexpr auto REMOVING_HOOK = u8"Textractor: removing hook: %s";
constexpr auto HOOK_FAILED = u8"Textractor: failed to insert hook";
constexpr auto TOO_MANY_HOOKS = u8"Textractor: too many hooks: can't insert";
constexpr auto FUNC_MISSING = u8"Textractor: function not present";
constexpr auto MODULE_MISSING = u8"Textractor: module not present";
constexpr auto GARBAGE_MEMORY = u8"Textractor: memory constantly changing, useless to read";

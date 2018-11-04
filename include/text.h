#pragma once

namespace
{
	auto ABOUT = L"Textractor beta v3.4.0 by Artikash\r\n"
		"Source code and more information available under GPLv3 at https://github.com/Artikash/Textractor";
	auto SELECT_PROCESS = "Select Process";
	auto INJECT_INFO = "If you don't see the process you want to inject, try running with admin rights\r\n"
		"You can also type in the process id";
	auto ADD_HOOK = "Add hook";
	auto CODE_INFODUMP = "Enter hook code\r\n"
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
	auto UNHOOK = "Unhook";
	auto REMOVE_HOOK = "Which hook to remove?";
	auto SELECT_EXTENSION = "Select Extension";
	auto EXTENSIONS = "Extensions (*.dll)";
	auto TOO_MANY_THREADS = L"Textractor: ERROR: too many text threads: can't create more";
	auto ALREADY_INJECTED = L"Textractor: ERROR: already injected";
	auto ARCHITECTURE_MISMATCH = L"Textractor: ERROR: architecture mismatch: try 32 bit Textractor instead";
	auto INJECT_FAILED = L"Textractor: ERROR: couldn't inject";
	auto INVALID_CODE = L"Textractor: invalid code";
	auto NO_HOOKS = :"Textractor: no hooks detected";
}

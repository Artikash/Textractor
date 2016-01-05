#include "TextBuffer.h"

DWORD WINAPI FlushThread(LPVOID lParam); // window.cpp

TextBuffer::TextBuffer(HWND edit) : hThread(IthCreateThread(FlushThread, (DWORD)this)),
hEdit(edit),
running(true)
{
}

TextBuffer::~TextBuffer()
{
	running = false;
	WaitForSingleObject(hThread.get(), 0);
}

void TextBuffer::AddText(LPCWSTR str, int len, bool line)
{
	CSLock lock(cs);
	if (len > 0)
		this->str.append(str, len);
	line_break = line;
}

void TextBuffer::Flush()
{
	CSLock lock(cs);
	if (line_break || str.empty())
		return;
	DWORD t = Edit_GetTextLength(hEdit);
	Edit_SetSel(hEdit, t, -1);
	Edit_ReplaceSel(hEdit, str.c_str());
	str.clear();
}

void TextBuffer::ClearBuffer()
{
	CSLock lock(cs);
	str.clear();
	line_break = false;
}

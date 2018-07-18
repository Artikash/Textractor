#include "TextBuffer.h"

DWORD WINAPI FlushThread(LPVOID lParam)
{
	TextBuffer* t = (TextBuffer*)lParam;
	while (t->Running())
	{
		t->Flush();
		Sleep(10);
	}
	return 0;
}

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

void TextBuffer::AddText(std::wstring text, bool line)
{
	CSLock lock(cs);
	this->str.append(text);
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

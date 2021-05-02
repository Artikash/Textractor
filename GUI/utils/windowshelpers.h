#pragma once

#include <QtWinExtras/QtWin>
class QIcon;
namespace WindowsHepers
{
	HICON GetIconHandlerFromExe(const wchar_t* const filePath);
	QIcon CreateQIconFromHIcon(const HICON hIcon);
}

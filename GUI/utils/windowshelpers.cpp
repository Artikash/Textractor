#include "windowshelpers.h"

#include <QApplication>
#include <QIcon>
#include <QStyle>
#include <QPixmap>
#include <QtWinExtras/QtWin>

#include <shellapi.h>

namespace WindowsHepers {
	HICON GetIconHandlerFromExe(const wchar_t* const filePath)
	{
		HICON bigIcon;
		HICON smallIcon;
		ExtractIconEx(filePath, 0, &bigIcon, &smallIcon, 1);
		return bigIcon != 0 ? bigIcon : smallIcon;
	}

	QIcon CreateQIconFromHIcon(const HICON hIcon)
	{
		if (hIcon)
		{
			const QPixmap& pixmap = QtWin::fromHICON(hIcon);
			return QIcon(pixmap);
		}
		const QStyle* style = QApplication::style();
		return style->standardIcon(QStyle::SP_ComputerIcon);
	}
}

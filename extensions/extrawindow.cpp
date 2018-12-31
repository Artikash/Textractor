#include "extension.h"
#include "defs.h"
#include "text.h"
#include <QDialog>
#include <QInputDialog>
#include <QColorDialog>
#include <QMenu>
#include <QLayout>
#include <QLabel>
#include <QPainter>
#include <QMouseEvent>
#include <QSettings>
#include <QTimer>

std::mutex m;

struct : QDialog
{
	void launch()
	{
		settings->beginGroup("Extra Window");
		(new QHBoxLayout(this))->addWidget(display = new QLabel("Right click to change settings", this));
		setWindowFlags(Qt::FramelessWindowHint);
		setAttribute(Qt::WA_TranslucentBackground);
		setSizeGripEnabled(true);
		show();

		auto setBackgroundColor = [=](QColor color)
		{
			if (!color.isValid()) return;
			if (color.alpha() == 0) color.setAlpha(1);
			bgColor = color;
			repaint();
			settings->setValue("BG Color", color);
		};
		auto setTextColor = [=](QColor color)
		{
			if (!color.isValid()) return;
			auto newPalette = display->palette();
			newPalette.setColor(QPalette::WindowText, color);
			display->setPalette(newPalette);
			settings->setValue("Text Color", color);
		};
		auto setFontSize = [=](int pt)
		{
			QFont newFont = display->font();
			newFont.setPointSize(pt);
			display->setFont(newFont);
			settings->setValue("Font Size", pt);
		};
		auto setTopmost = [=](bool topmost)
		{
			SetWindowPos((HWND)winId(), topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
			settings->setValue("Topmost", topmost);
		};
		setGeometry(settings->value("Window", geometry()).toRect());
		setTopmost(settings->value("Topmost", false).toBool());
		setFontSize(settings->value("Font Size", 16).toInt());
		setBackgroundColor(settings->value("BG Color", palette().window().color()).value<QColor>());
		setTextColor(settings->value("Text Color", display->palette().windowText().color()).value<QColor>());

		auto menu = new QMenu(this);
		menu->addAction("Topmost", setTopmost)->setCheckable(true);
		menu->addAction("BG Color", [=] { setBackgroundColor(QColorDialog::getColor(palette().window().color(), this, "BG Color", QColorDialog::ShowAlphaChannel)); });
		menu->addAction("Text Color", [=] { setTextColor(QColorDialog::getColor(display->palette().windowText().color(), this, "Text Color")); });
		menu->addAction("Font Size", [=] { setFontSize(QInputDialog::getInt(this, "Font Size", "", display->font().pointSize(), 0, INT_MAX, 1, nullptr, Qt::WindowCloseButtonHint)); });
		setContextMenuPolicy(Qt::CustomContextMenu);
		connect(this, &QDialog::customContextMenuRequested, menu, [=](QPoint point) { menu->exec(mapToGlobal(point)); });
		connect(this, &QDialog::destroyed, [=] { settings->setValue("Window", geometry()); });
	}

	void paintEvent(QPaintEvent*) override
	{
		QPainter(this).fillRect(rect(), bgColor);
	}

	void mousePressEvent(QMouseEvent* evt)
	{
		oldPos = evt->globalPos();
	}

	void mouseMoveEvent(QMouseEvent* evt)
	{
		const QPoint delta = evt->globalPos() - oldPos;
		move(x() + delta.x(), y() + delta.y());
		oldPos = evt->globalPos();
	}

	QColor bgColor = QPalette().window().color();
	QPoint oldPos;

	QSettings* settings = new QSettings(CONFIG_FILE, QSettings::IniFormat, this);
	QLabel* display;
}*window = nullptr;

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		QTimer::singleShot(0, []
		{
			std::lock_guard l(m);
			(window = new std::remove_pointer_t<decltype(window)>)->launch();
		});
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		std::lock_guard l(m);
		if (window != nullptr) window->settings->setValue("Window", window->geometry());
		if (lpReserved == NULL) // https://blogs.msdn.microsoft.com/oldnewthing/20120105-00/?p=8683
		{
			delete window;
			window = nullptr;
		}
	}
	break;
	}
	return TRUE;
}

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	std::lock_guard l(m);
	if (window == nullptr || !sentenceInfo["current select"]) return false;
	QMetaObject::invokeMethod(window, [=] { window->display->setText(QString::fromStdWString(sentence)); });
	return false;
}

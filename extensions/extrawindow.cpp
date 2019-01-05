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
public:
	void launch()
	{
		settings->beginGroup("Extra Window");
		(new QHBoxLayout(this))->addWidget(display = new QLabel(EXTRA_WINDOW_INFO, this));
		display->setAlignment(Qt::AlignTop);
		display->setWordWrap(true);
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
			settings->setValue(BG_COLOR, color);
		};
		auto setTextColor = [=](QColor color)
		{
			if (!color.isValid()) return;
			auto newPalette = display->palette();
			newPalette.setColor(QPalette::WindowText, color);
			display->setPalette(newPalette);
			settings->setValue(TEXT_COLOR, color);
		};
		auto setFontSize = [=](int pt)
		{
			QFont newFont = display->font();
			newFont.setPointSize(pt);
			display->setFont(newFont);
			settings->setValue(FONT_SIZE, pt);
		};
		auto setTopmost = [=](bool topmost)
		{
			SetWindowPos((HWND)winId(), topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
			settings->setValue(TOPMOST, topmost);
		};
		setGeometry(settings->value(WINDOW, geometry()).toRect());
		setTopmost(settings->value(TOPMOST, false).toBool());
		setFontSize(settings->value(FONT_SIZE, 16).toInt());
		setBackgroundColor(settings->value(BG_COLOR, palette().window().color()).value<QColor>());
		setTextColor(settings->value(TEXT_COLOR, display->palette().windowText().color()).value<QColor>());

		auto menu = new QMenu(this);
		auto topmost = menu->addAction(TOPMOST, setTopmost);
		topmost->setCheckable(true);
		topmost->setChecked(settings->value(TOPMOST).toBool());
		menu->addAction(BG_COLOR, [=] { setBackgroundColor(QColorDialog::getColor(bgColor, this, BG_COLOR, QColorDialog::ShowAlphaChannel)); });
		menu->addAction(TEXT_COLOR, [=] { setTextColor(QColorDialog::getColor(display->palette().windowText().color(), this, TEXT_COLOR, QColorDialog::ShowAlphaChannel)); });
		menu->addAction(FONT_SIZE, [=] { setFontSize(QInputDialog::getInt(this, FONT_SIZE, "", display->font().pointSize(), 0, INT_MAX, 1, nullptr, Qt::WindowCloseButtonHint)); });
		setContextMenuPolicy(Qt::CustomContextMenu);
		connect(this, &QDialog::customContextMenuRequested, menu, [=](QPoint point) { menu->exec(mapToGlobal(point)); });
		connect(this, &QDialog::destroyed, [=] { settings->setValue(WINDOW, geometry()); });
	}

	QSettings* settings = new QSettings(CONFIG_FILE, QSettings::IniFormat, this);
	QLabel* display;

private:
	void paintEvent(QPaintEvent*) override
	{
		QPainter(this).fillRect(rect(), bgColor);
	}

	void mousePressEvent(QMouseEvent* event)
	{
		oldPos = event->globalPos();
	}

	void mouseMoveEvent(QMouseEvent* event)
	{
		const QPoint delta = event->globalPos() - oldPos;
		move(x() + delta.x(), y() + delta.y());
		oldPos = event->globalPos();
	}

	QColor bgColor;
	QPoint oldPos;
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
		if (window != nullptr) window->settings->setValue(WINDOW, window->geometry());
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

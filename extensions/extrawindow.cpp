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
		display->setTextFormat(Qt::PlainText);
		display->setTextInteractionFlags(Qt::TextSelectableByMouse);
		display->setAlignment(Qt::AlignTop);
		display->setWordWrap(true);
		display->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
		setWindowFlags(Qt::FramelessWindowHint);
		setAttribute(Qt::WA_TranslucentBackground);
		setSizeGripEnabled(true);
		resize(400, 300);
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
		auto setLock = [=](bool lock)
		{
			locked = lock;
			setSizeGripEnabled(!lock);
			settings->setValue(SIZE_LOCK, lock);
		};
		setGeometry(settings->value(WINDOW, geometry()).toRect());
		setLock(settings->value(SIZE_LOCK, false).toBool());
		setTopmost(settings->value(TOPMOST, false).toBool());
		setFontSize(settings->value(FONT_SIZE, 16).toInt());
		setBackgroundColor(settings->value(BG_COLOR, palette().window().color()).value<QColor>());
		setTextColor(settings->value(TEXT_COLOR, display->palette().windowText().color()).value<QColor>());

		auto menu = new QMenu(display);
		auto topmost = menu->addAction(TOPMOST, setTopmost);
		topmost->setCheckable(true);
		topmost->setChecked(settings->value(TOPMOST, false).toBool());
		auto lock = menu->addAction(SIZE_LOCK, setLock);
		lock->setCheckable(true);
		lock->setChecked(settings->value(SIZE_LOCK, false).toBool());
		menu->addAction(BG_COLOR, [=] { setBackgroundColor(QColorDialog::getColor(bgColor, this, BG_COLOR, QColorDialog::ShowAlphaChannel)); });
		menu->addAction(TEXT_COLOR, [=] { setTextColor(QColorDialog::getColor(display->palette().windowText().color(), this, TEXT_COLOR, QColorDialog::ShowAlphaChannel)); });
		menu->addAction(FONT_SIZE, [=] { setFontSize(QInputDialog::getInt(this, FONT_SIZE, "", display->font().pointSize(), 0, INT_MAX, 1, nullptr, Qt::WindowCloseButtonHint)); });
		display->setContextMenuPolicy(Qt::CustomContextMenu);
		connect(display, &QLabel::customContextMenuRequested, [=](QPoint point) { menu->exec(mapToGlobal(point)); });
		connect(this, &QDialog::destroyed, [=] { settings->setValue(WINDOW, geometry()); });
	}

	QSettings* settings = new QSettings(CONFIG_FILE, QSettings::IniFormat, this);
	QLabel* display;

private:
	void paintEvent(QPaintEvent*) override
	{
		QPainter(this).fillRect(rect(), bgColor);
	}

	void mousePressEvent(QMouseEvent* event) override
	{
		oldPos = event->globalPos();
	}

	void mouseMoveEvent(QMouseEvent* event) override
	{
		const QPoint delta = event->globalPos() - oldPos;
		if (!locked) move(x() + delta.x(), y() + delta.y());
		oldPos = event->globalPos();
	}

	bool locked;
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
		if (window != nullptr)
		{
			window->settings->setValue(WINDOW, window->geometry());
			window->settings->sync();
		}
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

#include "qtcommon.h"
#include "extension.h"
#include "ui_extrawindow.h"
#include "defs.h"
#include <QColorDialog>
#include <QFontDialog>
#include <QMenu>
#include <QPainter>
#include <QMouseEvent>

extern const char* EXTRA_WINDOW_INFO;
extern const char* TOPMOST;
extern const char* SHOW_ORIGINAL;
extern const char* SHOW_ORIGINAL_INFO;
extern const char* SIZE_LOCK;
extern const char* BG_COLOR;
extern const char* TEXT_COLOR;
extern const char* FONT;
extern const char* SAVE_SETTINGS;

struct Window : QDialog
{
public:
	Window()
	{
		ui.setupUi(this);

		settings.beginGroup("Extra Window");
		setWindowFlags(Qt::FramelessWindowHint);
		setAttribute(Qt::WA_TranslucentBackground);
		QMetaObject::invokeMethod(this, [this]
		{
			show();

			QFont font = ui.display->font();
			if (font.fromString(settings.value(FONT, font.toString()).toString())) ui.display->setFont(font);
			setBackgroundColor(settings.value(BG_COLOR, palette().window().color()).value<QColor>());
			setTextColor(settings.value(TEXT_COLOR, ui.display->palette().windowText().color()).value<QColor>());
			setLock(settings.value(SIZE_LOCK, false).toBool());
			setTopmost(settings.value(TOPMOST, false).toBool());
			setGeometry(settings.value(WINDOW, geometry()).toRect());

			menu.addAction(FONT, this, &Window::RequestFont);
			menu.addAction(BG_COLOR, [this] { setBackgroundColor(QColorDialog::getColor(bgColor, this, BG_COLOR, QColorDialog::ShowAlphaChannel)); });
			menu.addAction(TEXT_COLOR, [this] { setTextColor(QColorDialog::getColor(ui.display->palette().windowText().color(), this, TEXT_COLOR, QColorDialog::ShowAlphaChannel)); });
			for (auto [name, default, slot] : Array<std::tuple<const char*, bool, void(Window::*)(bool)>>{
				{ TOPMOST, false, &Window::setTopmost },
				{ SIZE_LOCK, false, &Window::setLock },
				{ SHOW_ORIGINAL, true, &Window::setShowOriginal }
			})
			{
				auto action = menu.addAction(name, this, slot);
				action->setCheckable(true);
				action->setChecked(settings.value(name, default).toBool());
			}
			connect(ui.display, &QLabel::customContextMenuRequested, [this](QPoint point) { menu.exec(mapToGlobal(point)); });

			QMetaObject::invokeMethod(this, [this] { ui.display->setText(EXTRA_WINDOW_INFO); }, Qt::QueuedConnection);
		}, Qt::QueuedConnection);
	}

	~Window()
	{
		settings.setValue(WINDOW, geometry());
		settings.sync();
	}

	Ui::ExtraWindow ui;
	QSettings settings{ CONFIG_FILE, QSettings::IniFormat, this };

private:
	void RequestFont()
	{
		bool ok;
		if (QFont font = QFontDialog::getFont(&ok, ui.display->font(), this, FONT); ok)
		{
			settings.setValue(FONT, font.toString());
			ui.display->setFont(font);
		}
	};

	void setBackgroundColor(QColor color)
	{
		if (!color.isValid()) return;
		if (color.alpha() == 0) color.setAlpha(1);
		bgColor = color;
		repaint();
		settings.setValue(BG_COLOR, color);
	};

	void setTextColor(QColor color)
	{
		if (!color.isValid()) return;
		auto newPalette = ui.display->palette();
		newPalette.setColor(QPalette::WindowText, color);
		ui.display->setPalette(newPalette);
		settings.setValue(TEXT_COLOR, color);
	};

	void setTopmost(bool topmost)
	{
		SetWindowPos((HWND)winId(), topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
		settings.setValue(TOPMOST, topmost);
	};

	void setLock(bool lock)
	{
		locked = lock;
		setSizeGripEnabled(!lock);
		settings.setValue(SIZE_LOCK, lock);
	};

	void setShowOriginal(bool showOriginal)
	{
		if (!showOriginal) QMessageBox::information(this, SHOW_ORIGINAL, SHOW_ORIGINAL_INFO);
		settings.setValue(SHOW_ORIGINAL, showOriginal);
	};

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

	QMenu menu{ ui.display };
	bool locked = true;
	QColor bgColor;
	QPoint oldPos;
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (!sentenceInfo["current select"]) return false;

	QString qSentence = S(sentence);
	if (!window.settings.value(SHOW_ORIGINAL, true).toBool()) qSentence = qSentence.section('\n', qSentence.count('\n') / 2 + 1);

	QMetaObject::invokeMethod(&window, [=] { window.ui.display->setText(qSentence); });
	return false;
}

#include "qtcommon.h"
#include "extension.h"
#include "ui_extrawindow.h"
#include "defs.h"
#include <fstream>
#include <filesystem>
#include <process.h>
#include <QColorDialog>
#include <QFontDialog>
#include <QMenu>
#include <QPainter>
#include <QGraphicsEffect>
#include <QMouseEvent>
#include <QWheelEvent>

extern const char* EXTRA_WINDOW_INFO;
extern const char* TOPMOST;
extern const char* SHOW_ORIGINAL;
extern const char* SHOW_ORIGINAL_INFO;
extern const char* SIZE_LOCK;
extern const char* DICTIONARY;
extern const char* DICTIONARY_INSTRUCTIONS;
extern const char* BG_COLOR;
extern const char* TEXT_COLOR;
extern const char* TEXT_OUTLINE;
extern const char* OUTLINE_COLOR;
extern const char* OUTLINE_SIZE;
extern const char* OUTLINE_SIZE_INFO;
extern const char* FONT;
extern const char* SAVE_SETTINGS;

constexpr auto DICTIONARY_SAVE_FILE = u8"SavedDictionary.txt";

struct PrettyWindow : QDialog
{
	PrettyWindow(const char* name)
	{
		ui.setupUi(this);
		ui.display->setGraphicsEffect(&outliner);
		setWindowFlags(Qt::FramelessWindowHint);
		setAttribute(Qt::WA_TranslucentBackground);

		settings.beginGroup(name);
		QFont font = ui.display->font();
		if (font.fromString(settings.value(FONT, font.toString()).toString())) ui.display->setFont(font);
		setBgColor(settings.value(BG_COLOR, bgColor).value<QColor>());
		setTextColor(settings.value(TEXT_COLOR, textColor()).value<QColor>());
		outliner.color = settings.value(OUTLINE_COLOR, outliner.color).value<QColor>();
		outliner.size = settings.value(OUTLINE_SIZE, outliner.size).toDouble();
		menu.addAction(FONT, this, &PrettyWindow::RequestFont);
		menu.addAction(BG_COLOR, [this] { setBgColor(QColorDialog::getColor(bgColor, this, BG_COLOR, QColorDialog::ShowAlphaChannel)); });
		menu.addAction(TEXT_COLOR, [this] { setTextColor(QColorDialog::getColor(textColor(), this, TEXT_COLOR, QColorDialog::ShowAlphaChannel)); });
		QAction* outlineAction = menu.addAction(TEXT_OUTLINE, this, &PrettyWindow::setOutline);
		outlineAction->setCheckable(true);
		outlineAction->setChecked(outliner.size >= 0);
		connect(ui.display, &QLabel::customContextMenuRequested, [this](QPoint point) { menu.exec(mapToGlobal(point)); });
	}

	~PrettyWindow()
	{
		settings.sync();
	}

	Ui::ExtraWindow ui;

protected:
	QMenu menu{ ui.display };
	QSettings settings{ CONFIG_FILE, QSettings::IniFormat, this };

private:
	void RequestFont()
	{
		if (QFont font = QFontDialog::getFont(&ok, ui.display->font(), this, FONT); ok)
		{
			settings.setValue(FONT, font.toString());
			ui.display->setFont(font);
		}
	};

	void setBgColor(QColor color)
	{
		if (!color.isValid()) return;
		if (color.alpha() == 0) color.setAlpha(1);
		bgColor = color;
		repaint();
		settings.setValue(BG_COLOR, color.name(QColor::HexArgb));
	};

	QColor textColor()
	{
		return ui.display->palette().color(QPalette::WindowText);
	}

	void setTextColor(QColor color)
	{
		if (!color.isValid()) return;
		ui.display->setPalette(QPalette(color, {}, {}, {}, {}, {}, {}));
		settings.setValue(TEXT_COLOR, color.name(QColor::HexArgb));
	};

	void setOutline(bool enable)
	{
		if (enable)
		{
			QColor color = QColorDialog::getColor(outliner.color, this, OUTLINE_COLOR, QColorDialog::ShowAlphaChannel);
			if (color.isValid()) outliner.color = color;
			outliner.size = QInputDialog::getDouble(this, OUTLINE_SIZE, OUTLINE_SIZE_INFO, 0.5, 0, INT_MAX, 2, nullptr, Qt::WindowCloseButtonHint);
		}
		else outliner.size = -1;
		settings.setValue(OUTLINE_COLOR, outliner.color.name(QColor::HexArgb));
		settings.setValue(OUTLINE_SIZE, outliner.size);
	}

	void paintEvent(QPaintEvent*) override
	{
		QPainter(this).fillRect(rect(), bgColor);
	}

	QColor bgColor{ palette().window().color() };
	struct : QGraphicsEffect
	{
		void draw(QPainter* painter) override
		{
			if (size < 0) return drawSource(painter);
			QPoint offset;
			QPixmap pixmap = sourcePixmap(Qt::LogicalCoordinates, &offset);
			offset.setX(offset.x() + size);
			for (auto offset2 : Array<QPointF>{ { 0, 1 }, { 0, -1 }, { 1, 0 }, { -1, 0 }, { 1, 1 }, { 1, -1 }, { -1, 1 }, { -1, -1 } })
			{
				QImage outline = pixmap.toImage();
				QPainter outlinePainter(&outline);
				outlinePainter.setCompositionMode(QPainter::CompositionMode_SourceIn);
				outlinePainter.fillRect(outline.rect(), color);
				painter->drawImage(offset + offset2 * size, outline);
			}
			painter->drawPixmap(offset, pixmap);
		}
		QColor color{ Qt::black };
		double size = -1;
	} outliner;
};

class ExtraWindow : public PrettyWindow
{
public:
	ExtraWindow() :
		PrettyWindow("Extra Window")
	{
		ui.display->setTextFormat(Qt::PlainText);
		setGeometry(settings.value(WINDOW, geometry()).toRect());

		for (auto [name, default, slot] : Array<std::tuple<const char*, bool, void(ExtraWindow::*)(bool)>>{
			{ TOPMOST, false, &ExtraWindow::setTopmost },
			{ SIZE_LOCK, false, &ExtraWindow::setLock },
			{ SHOW_ORIGINAL, true, &ExtraWindow::setShowOriginal },
			{ DICTIONARY, false, &ExtraWindow::setUseDictionary },
		})
		{
			// delay processing anything until Textractor has finished initializing
			QMetaObject::invokeMethod(this, std::bind(slot, this, default = settings.value(name, default).toBool()), Qt::QueuedConnection);
			auto action = menu.addAction(name, this, slot);
			action->setCheckable(true);
			action->setChecked(default);
		}
		ui.display->installEventFilter(this);

		QMetaObject::invokeMethod(this, [this]
		{
			show();
			QMetaObject::invokeMethod(this, [this] { AddSentence(EXTRA_WINDOW_INFO); }, Qt::QueuedConnection);
		}, Qt::QueuedConnection);
	}

	~ExtraWindow()
	{
		settings.setValue(WINDOW, geometry());
	}

	void AddSentence(QString sentence)
	{
		if (!showOriginal) sentence = sentence.section('\n', sentence.count('\n') / 2 + 1);
		sentenceHistory.push_back(sentence);
		historyIndex = sentenceHistory.size() - 1;
		ui.display->setText(sentence);
	}

private:
	void setTopmost(bool topmost)
	{
		SetWindowPos((HWND)winId(), topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
		settings.setValue(TOPMOST, topmost);
	};

	void setLock(bool locked)
	{
		setSizeGripEnabled(!locked);
		settings.setValue(SIZE_LOCK, this->locked = locked);
	};

	void setShowOriginal(bool showOriginal)
	{
		if (!showOriginal && settings.value(SHOW_ORIGINAL, false).toBool()) QMessageBox::information(this, SHOW_ORIGINAL, SHOW_ORIGINAL_INFO);
		settings.setValue(SHOW_ORIGINAL, this->showOriginal = showOriginal);
	};

	void setUseDictionary(bool useDictionary)
	{
		if (useDictionary)
		{
			dictionaryWindow.UpdateDictionary();
			if (dictionaryWindow.dictionary.empty())
			{
				std::ofstream(DICTIONARY_SAVE_FILE) << u8"\ufeff" << DICTIONARY_INSTRUCTIONS;
				_spawnlp(_P_DETACH, "notepad", "notepad", DICTIONARY_SAVE_FILE, NULL); // show file to user
			}
		}
		settings.setValue(DICTIONARY, this->useDictionary = useDictionary);
	}

	bool eventFilter(QObject*, QEvent* event) override
	{
		if (useDictionary && event->type() == QEvent::MouseButtonRelease && ui.display->hasSelectedText())
		{
			dictionaryWindow.ui.display->setFixedWidth(ui.display->width());
			dictionaryWindow.setTerm(ui.display->text().mid(ui.display->selectionStart()));
			dictionaryWindow.move({ x(), y() - dictionaryWindow.height() });
		}
		if (event->type() == QEvent::MouseButtonPress) dictionaryWindow.hide();
		return false;
	}

	void mousePressEvent(QMouseEvent* event) override
	{
		dictionaryWindow.hide();
		oldPos = event->globalPos();
	}

	void mouseMoveEvent(QMouseEvent* event) override
	{
		if (!locked) move(pos() + event->globalPos() - oldPos);
		oldPos = event->globalPos();
	}

	void wheelEvent(QWheelEvent* event) override
	{
		int scroll = event->angleDelta().y();
		if (scroll > 0 && historyIndex > 0) ui.display->setText(sentenceHistory[--historyIndex]);
		if (scroll < 0 && historyIndex + 1 < sentenceHistory.size()) ui.display->setText(sentenceHistory[++historyIndex]);
	}

	bool locked, showOriginal, useDictionary;
	QPoint oldPos;
	std::vector<QString> sentenceHistory;
	int historyIndex = 0;

	class DictionaryWindow : public PrettyWindow
	{
	public:
		DictionaryWindow() :
			PrettyWindow("Dictionary Window")
		{
			ui.display->setSizePolicy({ QSizePolicy::Fixed, QSizePolicy::Minimum });
		}

		void UpdateDictionary()
		{
			try
			{
				if (dictionaryFileLastWrite == std::filesystem::last_write_time(DICTIONARY_SAVE_FILE)) return;
				dictionaryFileLastWrite = std::filesystem::last_write_time(DICTIONARY_SAVE_FILE);
			}
			catch (std::filesystem::filesystem_error) { return; }

			dictionary.clear();
			owningStorage.clear();

			auto StoreCopy = [&](const std::string& string)
			{
				return &*owningStorage.insert(owningStorage.end(), string.c_str(), string.c_str() + string.size() + 1);
			};

			std::string savedDictionary(std::istreambuf_iterator(std::ifstream(DICTIONARY_SAVE_FILE)), {});
			owningStorage.reserve(savedDictionary.size());
			for (size_t end = 0; ;)
			{
				size_t term = savedDictionary.find("|TERM|", end);
				size_t definition = savedDictionary.find("|DEFINITION|", term);
				if ((end = savedDictionary.find("|END|", definition)) == std::string::npos) break;
				auto storedDefinition = StoreCopy(savedDictionary.substr(definition + 12, end - definition - 12));
				for (size_t next; (next = savedDictionary.find("|TERM|", term + 1)) != std::string::npos && next < definition; term = next)
					dictionary.push_back({ StoreCopy(savedDictionary.substr(term + 6, next - term - 6)), storedDefinition });
				dictionary.push_back({ StoreCopy(savedDictionary.substr(term + 6, definition - term - 6)), storedDefinition });
			}
			auto oldData = owningStorage.data();
			owningStorage.shrink_to_fit();
			dictionary.shrink_to_fit();
			for (auto& [term, definition] : dictionary)
			{
				term += owningStorage.data() - oldData;
				definition += owningStorage.data() - oldData;
			}
			std::sort(dictionary.begin(), dictionary.end());
		}

		void setTerm(QString term)
		{
			UpdateDictionary();
			definitions.clear();
			definitionIndex = 0;
			std::unordered_set<std::string_view> definitionSet;
			for (QByteArray utf8term = term.left(200).toUtf8(); !utf8term.isEmpty(); utf8term.chop(1))
				for (auto [it, end] = std::equal_range(dictionary.begin(), dictionary.end(), DictionaryEntry{ utf8term }); it != end; ++it)
					if (definitionSet.emplace(it->definition).second)
						definitions.push_back(QStringLiteral("<h3>%1 (%3/%4)</h3>%2").arg(utf8term, it->definition));
			for (int i = 0; i < definitions.size(); ++i) definitions[i] = definitions[i].arg(i + 1).arg(definitions.size());
			ShowDefinition();
		}

		void ShowDefinition()
		{
			if (definitions.empty()) return;
			ui.display->setText(definitions[definitionIndex]);
			adjustSize();
			resize(width(), 1);
			show();
		}

		struct DictionaryEntry
		{
			const char* term;
			const char* definition;
			bool operator<(DictionaryEntry other) const { return strcmp(term, other.term) < 0; }
		};
		std::vector<DictionaryEntry> dictionary;

	private:
		void wheelEvent(QWheelEvent* event) override
		{
			int scroll = event->angleDelta().y();
			if (scroll > 0 && definitionIndex > 0) definitionIndex -= 1;
			if (scroll < 0 && definitionIndex + 1 < definitions.size()) definitionIndex += 1;
			int oldHeight = height();
			ShowDefinition();
			move(x(), y() + oldHeight - height());
		}

		std::filesystem::file_time_type dictionaryFileLastWrite;
		std::vector<char> owningStorage;
		std::vector<QString> definitions;
		int definitionIndex;
	} dictionaryWindow;
} extraWindow;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["current select"])	QMetaObject::invokeMethod(&extraWindow, [sentence = S(sentence)] { extraWindow.AddSentence(sentence); });
	return false;
}

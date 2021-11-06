#include "qtcommon.h"
#include "extension.h"
#include "ui_extrawindow.h"
#include "blockmarkup.h"
#include <fstream>
#include <process.h>
#include <QRegularExpression>
#include <QColorDialog>
#include <QFontDialog>
#include <QMenu>
#include <QPainter>
#include <QGraphicsEffect>
#include <QFontMetrics>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QAbstractNativeEventFilter>

extern const char* EXTRA_WINDOW_INFO;
extern const char* SENTENCE_TOO_BIG;
extern const char* MAX_SENTENCE_SIZE;
extern const char* TOPMOST;
extern const char* OPACITY;
extern const char* SHOW_ORIGINAL;
extern const char* SHOW_ORIGINAL_INFO;
extern const char* SIZE_LOCK;
extern const char* AUTO_RESIZE_WINDOW_HEIGHT;
extern const char* CLICK_THROUGH;
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
constexpr int CLICK_THROUGH_HOTKEY = 0xc0d0;

QColor colorPrompt(QWidget* parent, QColor default, const QString& title, bool customOpacity = true)
{
	QColor color = QColorDialog::getColor(default, parent, title);
	if (customOpacity) color.setAlpha(255 * QInputDialog::getDouble(parent, title, OPACITY, default.alpha() / 255.0, 0, 1, 3, nullptr, Qt::WindowCloseButtonHint));
	return color;
}

struct PrettyWindow : QDialog, Localizer
{
	PrettyWindow(const char* name)
	{
		ui.setupUi(this);
		ui.display->setGraphicsEffect(outliner = new Outliner);
		setWindowFlags(Qt::FramelessWindowHint);
		setAttribute(Qt::WA_TranslucentBackground);

		settings.beginGroup(name);
		QFont font = ui.display->font();
		if (font.fromString(settings.value(FONT, font.toString()).toString())) ui.display->setFont(font);
		SetBackgroundColor(settings.value(BG_COLOR, backgroundColor).value<QColor>());
		SetTextColor(settings.value(TEXT_COLOR, TextColor()).value<QColor>());
		outliner->color = settings.value(OUTLINE_COLOR, outliner->color).value<QColor>();
		outliner->size = settings.value(OUTLINE_SIZE, outliner->size).toDouble();
		menu.addAction(FONT, this, &PrettyWindow::RequestFont);
		menu.addAction(BG_COLOR, [this] { SetBackgroundColor(colorPrompt(this, backgroundColor, BG_COLOR)); });
		menu.addAction(TEXT_COLOR, [this] { SetTextColor(colorPrompt(this, TextColor(), TEXT_COLOR)); });
		QAction* outlineAction = menu.addAction(TEXT_OUTLINE, this, &PrettyWindow::SetOutline);
		outlineAction->setCheckable(true);
		outlineAction->setChecked(outliner->size >= 0);
		connect(ui.display, &QLabel::customContextMenuRequested, [this](QPoint point) { menu.exec(mapToGlobal(point)); });
	}

	~PrettyWindow()
	{
		settings.sync();
	}

	Ui::ExtraWindow ui;

protected:
	QMenu menu{ ui.display };
	Settings settings{ this };

private:
	void RequestFont()
	{
		if (QFont font = QFontDialog::getFont(&ok, ui.display->font(), this, FONT); ok)
		{
			settings.setValue(FONT, font.toString());
			ui.display->setFont(font);
		}
	};

	void SetBackgroundColor(QColor color)
	{
		if (!color.isValid()) return;
		if (color.alpha() == 0) color.setAlpha(1);
		backgroundColor = color;
		repaint();
		settings.setValue(BG_COLOR, color.name(QColor::HexArgb));
	};

	QColor TextColor()
	{
		return ui.display->palette().color(QPalette::WindowText);
	}

	void SetTextColor(QColor color)
	{
		if (!color.isValid()) return;
		ui.display->setPalette(QPalette(color, {}, {}, {}, {}, {}, {}));
		settings.setValue(TEXT_COLOR, color.name(QColor::HexArgb));
	};

	void SetOutline(bool enable)
	{
		if (enable)
		{
			QColor color = colorPrompt(this, outliner->color, OUTLINE_COLOR);
			if (color.isValid()) outliner->color = color;
			outliner->size = QInputDialog::getDouble(this, OUTLINE_SIZE, OUTLINE_SIZE_INFO, 0.5, 0, INT_MAX, 2, nullptr, Qt::WindowCloseButtonHint);
		}
		else outliner->size = -1;
		settings.setValue(OUTLINE_COLOR, outliner->color.name(QColor::HexArgb));
		settings.setValue(OUTLINE_SIZE, outliner->size);
	}

	void paintEvent(QPaintEvent*) override
	{
		QPainter(this).fillRect(rect(), backgroundColor);
	}

	QColor backgroundColor{ palette().window().color() };
	struct Outliner : QGraphicsEffect
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
	}* outliner;
};

class ExtraWindow : public PrettyWindow, QAbstractNativeEventFilter
{
public:
	ExtraWindow() : PrettyWindow("Extra Window")
	{
		ui.display->setTextFormat(Qt::PlainText);
		if (settings.contains(WINDOW) && QApplication::screenAt(settings.value(WINDOW).toRect().bottomRight())) setGeometry(settings.value(WINDOW).toRect());
		maxSentenceSize = settings.value(MAX_SENTENCE_SIZE, maxSentenceSize).toInt();

		for (auto [name, default, slot] : Array<const char*, bool, void(ExtraWindow::*)(bool)>{
			{ TOPMOST, false, &ExtraWindow::SetTopmost },
			{ SIZE_LOCK, false, &ExtraWindow::SetLock },
			{ AUTO_RESIZE_WINDOW_HEIGHT, false, &ExtraWindow::SetAutoResizeHeight },
			{ SHOW_ORIGINAL, true, &ExtraWindow::SetShowOriginal },
			{ DICTIONARY, false, &ExtraWindow::SetUseDictionary },
		})
		{
			// delay processing anything until Textractor has finished initializing
			QMetaObject::invokeMethod(this, std::bind(slot, this, default = settings.value(name, default).toBool()), Qt::QueuedConnection);
			auto action = menu.addAction(name, this, slot);
			action->setCheckable(true);
			action->setChecked(default);
		}

		menu.addAction(CLICK_THROUGH, this, &ExtraWindow::ToggleClickThrough);

		menu.addAction(MAX_SENTENCE_SIZE, this, [this]
		{
			settings.setValue(MAX_SENTENCE_SIZE, maxSentenceSize = QInputDialog::getInt(this, MAX_SENTENCE_SIZE, "", maxSentenceSize, 0, INT_MAX, 1, nullptr, Qt::WindowCloseButtonHint));
		});
		ui.display->installEventFilter(this);
		ui.display->setMouseTracking(true);
		qApp->installNativeEventFilter(this);

		QMetaObject::invokeMethod(this, [this]
		{
			RegisterHotKey((HWND)winId(), CLICK_THROUGH_HOTKEY, MOD_SHIFT | MOD_NOREPEAT, 0x58);
			show();
			AddSentence(EXTRA_WINDOW_INFO);
		}, Qt::QueuedConnection);
	}

	~ExtraWindow()
	{
		settings.setValue(WINDOW, geometry());
	}

	void AddSentence(QString sentence)
	{
		if (sentence.size() > maxSentenceSize) sentence = SENTENCE_TOO_BIG;
		if (!showOriginal && sentence.contains(u8"\x200b \n")) sentence = sentence.split(u8"\x200b \n")[1];
		sanitize(sentence);
		sentence.chop(std::distance(std::remove(sentence.begin(), sentence.end(), QChar::Tabulation), sentence.end()));
		sentenceHistory.push_back(sentence);
		historyIndex = sentenceHistory.size() - 1;
		ui.display->setText(sentence);

		AutoResize(sentence);
	}

private:
	void SetTopmost(bool topmost)
	{
		for (auto window : { winId(), dictionaryWindow.winId() })
			SetWindowPos((HWND)window, topmost ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
		settings.setValue(TOPMOST, topmost);
	};

	void SetLock(bool locked)
	{
		setSizeGripEnabled(!locked);
		settings.setValue(SIZE_LOCK, this->locked = locked);
	};

	void SetAutoResizeHeight(bool autoResizeHeight)
	{
		settings.setValue(AUTO_RESIZE_WINDOW_HEIGHT, this->autoResizeHeight = autoResizeHeight);

		// If we disable this then we need to reset window to a default height. For now we will just use value from settings
		if (!autoResizeHeight && settings.contains(WINDOW) && QApplication::screenAt(settings.value(WINDOW).toRect().bottomRight()))
		{
			setGeometry(settings.value(WINDOW).toRect());
		}
	};

	void AutoResize(QString sentence)
	{
		if (!autoResizeHeight) return;

		QFontMetrics fontMetrics(ui.display->font(), ui.display);
		auto boundingRect = fontMetrics.boundingRect(0, 0, width()-20, INT_MAX, Qt::TextWordWrap, sentence);
		int newHeight = boundingRect.height() + 30;
		int currHeight = height();

		if (newHeight != currHeight) {
			QSize s = size();
			s.setWidth(width());
			s.setHeight(newHeight);
			resize(s);
		}
	}

	void ToggleClickThrough()
	{
		if (clickThrough = !clickThrough)
		{
			setAttribute(Qt::WA_TransparentForMouseEvents, true);
			setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);
		} else {
			setAttribute(Qt::WA_TransparentForMouseEvents , false);
			//setWindowFlags(windowFlags() & ~Qt::WindowStaysOnTopHint);  // doesn't work
			setWindowFlags(Qt::FramelessWindowHint);
			SetTopmost(settings.value(TOPMOST, false).toBool());
		}
		show();
	};

	void SetShowOriginal(bool showOriginal)
	{
		if (!showOriginal && settings.value(SHOW_ORIGINAL, false).toBool()) QMessageBox::information(this, SHOW_ORIGINAL, SHOW_ORIGINAL_INFO);
		settings.setValue(SHOW_ORIGINAL, this->showOriginal = showOriginal);
	};

	void SetUseDictionary(bool useDictionary)
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

	void ComputeDictionaryPosition(QPoint mouse)
	{
		QString sentence = ui.display->text();
		const QFont& font = ui.display->font();
		if (cachedDisplayInfo.CompareExchange(ui.display))
		{
			QFontMetrics fontMetrics(font, ui.display);
			textPositionMap.clear();
			for (int i = 0, height = 0, lineBreak = 0; i < sentence.size(); ++i)
			{
				int block = 1;
				for (int charHeight = fontMetrics.boundingRect(0, 0, 1, INT_MAX, Qt::TextWordWrap, sentence.mid(i, 1)).height();
					i + block < sentence.size() && fontMetrics.boundingRect(0, 0, 1, INT_MAX, Qt::TextWordWrap, sentence.mid(i, block + 1)).height() < charHeight * 1.5; ++block);
				auto boundingRect = fontMetrics.boundingRect(0, 0, ui.display->width(), INT_MAX, Qt::TextWordWrap, sentence.left(i + block));
				if (boundingRect.height() > height)
				{
					height = boundingRect.height();
					lineBreak = i;
				}
				textPositionMap.push_back({
					fontMetrics.boundingRect(0, 0, ui.display->width(), INT_MAX, Qt::TextWordWrap, sentence.mid(lineBreak, i - lineBreak + 1)).width(),
					height
				});
			}
		}
		int i;
		for (i = 0; i < textPositionMap.size(); ++i) if (textPositionMap[i].y() > mouse.y() && textPositionMap[i].x() > mouse.x()) break;
		if (i == textPositionMap.size() || (mouse - textPositionMap[i]).manhattanLength() > font.pointSize() * 3) return dictionaryWindow.hide();
		if (sentence.mid(i) == dictionaryWindow.term) return dictionaryWindow.ShowDefinition();
		dictionaryWindow.ui.display->setFixedWidth(ui.display->width() * 3 / 4);
		dictionaryWindow.SetTerm(sentence.mid(i));
		int left = i == 0 ? 0 : textPositionMap[i - 1].x(), right = textPositionMap[i].x(),
			x = textPositionMap[i].x() > ui.display->width() / 2 ? -dictionaryWindow.width() + (right * 3 + left) / 4 : (left * 3 + right) / 4, y = 0;
		for (auto point : textPositionMap) if (point.y() > y && point.y() < textPositionMap[i].y()) y = point.y();
		dictionaryWindow.move(ui.display->mapToGlobal(QPoint(x, y - dictionaryWindow.height())));
	}

	bool nativeEventFilter(const QByteArray&, void* message, long* result) override
	{
		auto msg = (MSG*)message;
		if (msg->message != WM_HOTKEY || msg->wParam != CLICK_THROUGH_HOTKEY) return false;
		ToggleClickThrough();
		return true;
	}

	bool eventFilter(QObject*, QEvent* event) override
	{
		if (useDictionary && event->type() == QEvent::MouseMove) ComputeDictionaryPosition(((QMouseEvent*)event)->localPos().toPoint());
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
		AutoResize(sentenceHistory[historyIndex]);
	}

	bool locked, autoResizeHeight, showOriginal, useDictionary, clickThrough;
	int maxSentenceSize = 1000;
	QPoint oldPos;

	class
	{
	public:
		bool CompareExchange(QLabel* display)
		{
			if (display->text() == text && display->font() == font && display->width() == width) return false;
			text = display->text();
			font = display->font();
			width = display->width();
			return true;
		}

	private:
		QString text;
		QFont font;
		int width;
	} cachedDisplayInfo;
	std::vector<QPoint> textPositionMap;

	std::vector<QString> sentenceHistory;
	int historyIndex = 0;

	class DictionaryWindow : public PrettyWindow
	{
	public:
		DictionaryWindow() : PrettyWindow("Dictionary Window")
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
			charStorage.clear();

			auto StoreCopy = [&](std::string_view string)
			{
				auto location = &*charStorage.insert(charStorage.end(), string.begin(), string.end());
				charStorage.push_back(0);
				return location;
			};

			charStorage.reserve(std::filesystem::file_size(DICTIONARY_SAVE_FILE));
			std::ifstream stream(DICTIONARY_SAVE_FILE);
			BlockMarkupIterator savedDictionary(stream, Array<std::string_view>{ "|TERM|", "|DEFINITION|" });
			while (auto read = savedDictionary.Next())
			{
				const auto& [terms, definition] = read.value();
				auto storedDefinition = StoreCopy(definition);
				std::string_view termsView = terms;
				size_t start = 0, end = termsView.find("|TERM|");
				while (end != std::string::npos)
				{
					dictionary.push_back(DictionaryEntry{ StoreCopy(termsView.substr(start, end - start)), storedDefinition });
					start = end + 6;
					end = termsView.find("|TERM|", start);
				}
				dictionary.push_back(DictionaryEntry{ StoreCopy(termsView.substr(start)), storedDefinition });
			}
			std::stable_sort(dictionary.begin(), dictionary.end());

			inflections.clear();
			stream.seekg(0);
			BlockMarkupIterator savedInflections(stream, Array<std::string_view>{ "|ROOT|", "|INFLECTS TO|", "|NAME|" });
			while (auto read = savedInflections.Next())
			{
				const auto& [root, inflectsTo, name] = read.value();
				if (!inflections.emplace_back(Inflection{
					S(root),
					QRegularExpression(QRegularExpression::anchoredPattern(S(inflectsTo)), QRegularExpression::UseUnicodePropertiesOption),
					S(name)
				}).inflectsTo.isValid()) TEXTRACTOR_MESSAGE(L"Invalid regex: %s", StringToWideString(inflectsTo));
			}
		}

		void SetTerm(QString term)
		{
			this->term = term;
			UpdateDictionary();
			definitions.clear();
			definitionIndex = 0;
			std::unordered_set<const char*> foundDefinitions;
			for (term = term.left(100); !term.isEmpty(); term.chop(1))
				for (const auto& [rootTerm, definition, inflections] : LookupDefinitions(term, foundDefinitions))
					definitions.push_back(
						QStringLiteral("<h3>%1 (%5/%6)</h3><small>%2%3</small>%4").arg(
							term.split("<<")[0].toHtmlEscaped(),
							rootTerm.split("<<")[0].toHtmlEscaped(),
							inflections.join(""),
							definition
						)
					);
			for (int i = 0; i < definitions.size(); ++i) definitions[i] = definitions[i].arg(i + 1).arg(definitions.size());
			ShowDefinition();
		}

		void ShowDefinition()
		{
			if (definitions.empty()) return hide();
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
		QString term;

	private:
		struct LookupResult
		{
			QString term;
			QString definition;
			QStringList inflectionsUsed;
		};
		std::vector<LookupResult> LookupDefinitions(QString term, std::unordered_set<const char*>& foundDefinitions, QStringList inflectionsUsed = {})
		{
			std::vector<LookupResult> results;
			for (auto [it, end] = std::equal_range(dictionary.begin(), dictionary.end(), DictionaryEntry{ term.toUtf8() }); it != end; ++it)
				if (foundDefinitions.emplace(it->definition).second) results.push_back({ term, it->definition, inflectionsUsed });
			for (const auto& inflection : inflections) if (auto match = inflection.inflectsTo.match(term); match.hasMatch())
			{
				QStringList currentInflectionsUsed = inflectionsUsed;
				currentInflectionsUsed.push_front(inflection.name);
				QString root;
				for (const auto& ch : inflection.root) root += ch.isDigit() ? match.captured(ch.digitValue()) : ch;
				for (const auto& definition : LookupDefinitions(root, foundDefinitions, currentInflectionsUsed)) results.push_back(definition);
			}
			return results;
		}

		void wheelEvent(QWheelEvent* event) override
		{
			int scroll = event->angleDelta().y();
			if (scroll > 0 && definitionIndex > 0) definitionIndex -= 1;
			if (scroll < 0 && definitionIndex + 1 < definitions.size()) definitionIndex += 1;
			int oldHeight = height();
			ShowDefinition();
			move(x(), y() + oldHeight - height());
		}

		struct Inflection
		{
			QString root;
			QRegularExpression inflectsTo;
			QString name;
		};
		std::vector<Inflection> inflections;

		std::filesystem::file_time_type dictionaryFileLastWrite;
		std::vector<char> charStorage;
		std::vector<QString> definitions;
		int definitionIndex;
	} dictionaryWindow;
} extraWindow;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	if (sentenceInfo["current select"] && sentenceInfo["text number"] != 0)
		QMetaObject::invokeMethod(&extraWindow, [sentence = S(sentence)] { extraWindow.AddSentence(sentence); });
	return false;
}

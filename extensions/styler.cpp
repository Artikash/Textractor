#include "qtcommon.h"
#include "extension.h"
#include <fstream>
#include <QPlainTextEdit>

extern const char* LOAD_SCRIPT;

constexpr auto STYLE_SAVE_FILE = u8"Textractor.css";

class Window : public QDialog, Localizer
{
public:
	Window()
		: QDialog(nullptr, Qt::WindowMinMaxButtonsHint)
	{
		connect(&loadButton, &QPushButton::clicked, this, &Window::LoadScript);

		if (scriptEditor.toPlainText().isEmpty()) scriptEditor.setPlainText("/*https://doc.qt.io/qt-5/stylesheet-syntax.html*/");
		layout.addWidget(&scriptEditor);
		layout.addWidget(&loadButton);

		resize(800, 600);
		setWindowTitle("Styler");
		QMetaObject::invokeMethod(this, &QWidget::show, Qt::QueuedConnection);

		LoadScript();
	}

	~Window()
	{
		Save();
	}

private:
	void LoadScript()
	{
		qApp->setStyleSheet(scriptEditor.toPlainText());
		Save();
	}

	void Save()
	{
		QTextFile(STYLE_SAVE_FILE, QIODevice::WriteOnly | QIODevice::Truncate).write(scriptEditor.toPlainText().toUtf8());
	}

	QHBoxLayout layout{ this };
	QPlainTextEdit scriptEditor{ QTextFile(STYLE_SAVE_FILE, QIODevice::ReadOnly).readAll(), this };
	QPushButton loadButton{ LOAD_SCRIPT, this };
} window;

bool ProcessSentence(std::wstring& sentence, SentenceInfo sentenceInfo)
{
	return false;
}

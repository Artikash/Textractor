#ifndef EXTENSIONS_H
#define EXTENSIONS_H

#include "qtcommon.h"
#include <QListWidget>
#include <QDragEnterEvent>
#include <QDropEvent>

namespace Ui
{
	class ExtenWindow;
}

bool DispatchSentenceToExtensions(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo);

class ExtenWindow : public QMainWindow
{
	Q_OBJECT

public:
	explicit ExtenWindow(QWidget* parent = nullptr);
	~ExtenWindow();

private slots:
	void on_addButton_clicked();
	void on_rmvButton_clicked();

private:
	void Add(QFileInfo extenFile);
	void Sync();
	bool eventFilter(QObject* target, QEvent* event);
	void dragEnterEvent(QDragEnterEvent* event);
	void dropEvent(QDropEvent* event);

	Ui::ExtenWindow* ui;
	QListWidget* extenList;
};

#endif // EXTENSIONS_H

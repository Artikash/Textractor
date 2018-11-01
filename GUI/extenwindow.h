#ifndef EXTENSIONS_H
#define EXTENSIONS_H

#include "qtcommon.h"
#include <shared_mutex>
#include <QListWidget>

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
	bool eventFilter(QObject* target, QEvent* event);
	void Sync();

	Ui::ExtenWindow* ui;
	QFile extenSaveFile = QFile("Extensions.txt");
	QListWidget* extenList;
};

#endif // EXTENSIONS_H

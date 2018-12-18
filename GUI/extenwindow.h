#pragma once

#include "qtcommon.h"
#include <QDragEnterEvent>
#include <QDropEvent>

namespace Ui
{
	class ExtenWindow;
}

bool DispatchSentenceToExtensions(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo);

class ExtenWindow : public QMainWindow
{
public:
	explicit ExtenWindow(QWidget* parent = nullptr);
	~ExtenWindow();

private:
	void Add(QFileInfo extenFile);
	void Sync();
	bool eventFilter(QObject* target, QEvent* event);
	void dragEnterEvent(QDragEnterEvent* event);
	void dropEvent(QDropEvent* event);

	Ui::ExtenWindow* ui;
};

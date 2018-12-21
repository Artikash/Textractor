#pragma once

#include "qtcommon.h"

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
	bool eventFilter(QObject* target, QEvent* event) override;
	void keyPressEvent(QKeyEvent* event) override;
	void dragEnterEvent(QDragEnterEvent* event) override;
	void dropEvent(QDropEvent* event) override;

	Ui::ExtenWindow* ui;
};

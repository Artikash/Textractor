#pragma once

#include "qtcommon.h"

namespace Ui
{
	class ExtenWindow;
}

struct InfoForExtension
{
	const char* name;
	int64_t value;
};

bool DispatchSentenceToExtensions(std::wstring& sentence, const InfoForExtension* miscInfo);

class ExtenWindow : public QMainWindow
{
public:
	explicit ExtenWindow(QWidget* parent = nullptr);
	~ExtenWindow();

private:
	inline static constexpr auto EXTEN_SAVE_FILE = u8"SavedExtensions.txt";

	void Add(QFileInfo extenFile);
	void Sync();
	bool eventFilter(QObject* target, QEvent* event) override;
	void keyPressEvent(QKeyEvent* event) override;
	void dragEnterEvent(QDragEnterEvent* event) override;
	void dropEvent(QDropEvent* event) override;

	Ui::ExtenWindow* ui;
};

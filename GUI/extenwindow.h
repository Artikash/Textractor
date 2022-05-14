#pragma once

#include "qtcommon.h"

struct InfoForExtension
{
	const char* name;
	int64_t value;
};

bool DispatchSentenceToExtensions(std::wstring& sentence, const InfoForExtension* sentenceInfo);
void CleanupExtensions(); // must call this before exiting the program, only way to uphold guarantee that DllMain and OnNewSentence won't be called concurrently
void loadExtensions(std::wstring repositoryDir = L"./"); 

class ExtenWindow : public QMainWindow
{
public:
	explicit ExtenWindow(QWidget* parent = nullptr);

private:
	bool eventFilter(QObject* target, QEvent* event) override;
	void keyPressEvent(QKeyEvent* event) override;
	void dragEnterEvent(QDragEnterEvent* event) override;
	void dropEvent(QDropEvent* event) override;
};

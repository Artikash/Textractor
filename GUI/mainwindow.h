#pragma once

#include "qtcommon.h"

class MainWindow : public QMainWindow
{
public:
	explicit MainWindow(QWidget *parent = nullptr);
	~MainWindow();
private:
	void closeEvent(QCloseEvent*);
};

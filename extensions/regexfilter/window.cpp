#include "window.h"
#include "ui_window.h"
#include <QLabel>

Window::Window(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::Window)
{
	ui->setupUi(this);
}

Window::~Window()
{
	delete ui;
}

void Window::on_regexInput_textEdited(const QString& newRegex)
{
	QLabel* info = findChild<QLabel*>("info");
	std::lock_guard<std::mutex> l(m);
	try { regex = newRegex.toStdWString(); }
	catch (...) { return findChild<QLabel*>("info")->setText("Invalid regex"); }
	findChild<QLabel*>("info")->setText("Currently filtering: " + newRegex);
}

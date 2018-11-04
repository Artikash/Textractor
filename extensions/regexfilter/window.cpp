#include "window.h"
#include "ui_window.h"

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
	std::lock_guard<std::mutex> lock(locker);
	try { regex = newRegex.toStdWString(); }
	catch (...) {}
}

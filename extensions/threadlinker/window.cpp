#include "window.h"
#include "ui_window.h"
#include <QInputDialog>

Window::Window(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::Window)
{
	ui->setupUi(this);
	threadLinkList = findChild<QListWidget*>("threadLinkList");
}

Window::~Window()
{
	delete ui;
}

void Window::on_linkButton_clicked()
{
	bool ok1, ok2, ok3, ok4;
	int from = QInputDialog::getText(this, "Link From", "Thread number to link from?", QLineEdit::Normal, "", &ok1, Qt::WindowCloseButtonHint).toInt(&ok2, 16);
	int to = QInputDialog::getText(this, "Link To", "Thread number to link to?", QLineEdit::Normal, "", &ok3, Qt::WindowCloseButtonHint).toInt(&ok4, 16);
	if (ok1 && ok2 && ok3 && ok4)
	{
		std::lock_guard l(m);
		linkedTextHandles[from].insert(to);
		threadLinkList->addItem(QString::number(from, 16) + "->" + QString::number(to, 16));
	}
}

void Window::on_unlinkButton_clicked()
{
	std::lock_guard l(m);
	QStringList link = threadLinkList->currentItem()->text().split("->");
	threadLinkList->takeItem(threadLinkList->currentRow());
	linkedTextHandles[link[0].toInt(nullptr, 16)].erase(link[1].toInt(nullptr, 16));
}

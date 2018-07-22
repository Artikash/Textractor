#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "QMessageBox"
#include "qlineedit.h"
#include <Windows.h>
#include "../texthook/host.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->centralWidget->children().at(0), SIGNAL(returnPressed()), this, SLOT(onCommand()));
    StartHost();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::onCommand()
{
    QLineEdit* lineEdit = (QLineEdit*)sender();
    QMessageBox::information(this, "called", lineEdit->text());
}

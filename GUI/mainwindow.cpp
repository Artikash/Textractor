#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "QMessageBox"
#include "QLineEdit"
#include "QTableWidget"
#include "QInputDialog"
#include <Windows.h>
#include <qdebug.h>
#include <Psapi.h>
#include "../texthook/host.h"

QTableWidget* processList;

QString GetModuleName(DWORD processId, HMODULE module = NULL)
{
    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameExW(handle, module, buffer, MAX_PATH);
    return QString::fromWCharArray(wcsrchr(buffer, L'\\') + 1);
}

void OnProcessAttach(DWORD processId)
{
    processList->setItem(processList->rowCount(), 0, new QTableWidgetItem(QString::number(processId)));
}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    Host::Start();
    ui->setupUi(this);

    processList = this->findChild<QTableWidget*>("processList");
    Host::RegisterProcessAttachCallback([](DWORD processId)
    {
        processList->insertRow(processList->rowCount());
        processList->setItem(processList->rowCount() - 1, 0, new QTableWidgetItem(QString::number(processId)));
        processList->setItem(processList->rowCount() - 1, 1, new QTableWidgetItem(GetModuleName(processId)));
    });
    Host::Open();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_attachButton_clicked()
{
    //processList->insertRow(processList->rowCount());
    //processList->setItem(processList->rowCount() - 1, 0, new QTableWidgetItem(QString::number(6000)));
    Host::InjectProcess(QInputDialog::getInt(this, "Process ID?", ""));
}

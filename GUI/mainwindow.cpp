#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "QCoreApplication"
#include "QTextBrowser"
#include "QMessageBox"
#include "QComboBox"
#include "QLineEdit"
#include "QInputDialog"
#include <QCursor>
#include <Qt>
#include <Windows.h>
#include <qdebug.h>
#include <Psapi.h>
#include "../texthook/host.h"

QMainWindow* mainWindow;
QComboBox* processCombo;
QComboBox* ttCombo;
QTextBrowser* textOutput;

QString GetModuleName(DWORD processId, HMODULE module = NULL)
{
    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameExW(handle, module, buffer, MAX_PATH);
    CloseHandle(handle);
    return QString::fromWCharArray(wcsrchr(buffer, L'\\') + 1);
}

QString ProcessString(DWORD processId)
{
    return QString("%1: %2").arg(QString::number(processId), GetModuleName(processId));
}

QString TextThreadString(TextThread* thread)
{
    ThreadParameter tp = thread->GetThreadParameter();
    return QString("%1:%2:%3:%4:%5: ").arg(
        QString::number(thread->Number()),
        QString::number(tp.pid),
        QString::number(tp.hook, 16),
        QString::number(tp.retn, 16),
        QString::number(tp.spl, 16)
    ).toUpper() + QString::fromWCharArray(Host::GetHookName(tp.pid, tp.hook).c_str());
}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    hostSignaller(new HostSignaller)
{
    ui->setupUi(this);
    mainWindow = this;
    processCombo = mainWindow->findChild<QComboBox*>("processCombo");
    ttCombo = mainWindow->findChild<QComboBox*>("ttCombo");
    textOutput = mainWindow->findChild<QTextBrowser*>("textOutput");

    hostSignaller->Initialize();
    connect(hostSignaller, &HostSignaller::AddProcess, this, &MainWindow::AddProcess);
    connect(hostSignaller, &HostSignaller::RemoveProcess, this, &MainWindow::RemoveProcess);
    connect(hostSignaller, &HostSignaller::AddThread, this, &MainWindow::AddThread);
    connect(hostSignaller, &HostSignaller::RemoveThread, this, &MainWindow::RemoveThread);
    connect(hostSignaller, &HostSignaller::ThreadOutput, this, &MainWindow::ThreadOutput);
    Host::Open();
}

MainWindow::~MainWindow()
{
    Host::Close();
    delete hostSignaller;
    delete ui;
}

void MainWindow::AddProcess(unsigned int processId)
{
    processCombo->addItem(ProcessString(processId));
}

void MainWindow::RemoveProcess(unsigned int processId)
{
    processCombo->removeItem(processCombo->findText(QString::number(processId), Qt::MatchStartsWith));
}

void MainWindow::AddThread(TextThread* thread)
{
    ttCombo->addItem(TextThreadString(thread));
}

void MainWindow::RemoveThread(TextThread* thread)
{
    int threadIndex = ttCombo->findText(QString::number(thread->Number()), Qt::MatchStartsWith);
    ttCombo->removeItem(threadIndex);
    if (threadIndex == ttCombo->currentIndex())
    {
        ttCombo->setCurrentIndex(0);
        on_ttCombo_activated(0);
    }
    delete thread;
}

void MainWindow::ThreadOutput(TextThread* thread, QString output)
{
    if (TextThreadString(thread) == ttCombo->currentText())
    {
       textOutput->moveCursor(QTextCursor::End);
       textOutput->insertPlainText(output);
       textOutput->moveCursor(QTextCursor::End);
    }
}

void MainWindow::on_attachButton_clicked()
{
    Host::InjectProcess(QInputDialog::getInt(this, "Process ID?", "You can find this under Task Manager -> Details"));
}

void MainWindow::on_detachButton_clicked()
{
    Host::DetachProcess(processCombo->currentText().split(":")[0].toInt());
}

void MainWindow::on_ttCombo_activated(int index)
{
    textOutput->setText(QString::fromWCharArray(Host::GetThread(ttCombo->itemText(index).split(":")[0].toInt())->GetStore().c_str()));
}

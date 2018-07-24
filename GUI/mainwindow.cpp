#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "QTextBrowser"
#include "QMessageBox"
#include "QComboBox"
#include "QLineEdit"
#include "QTableWidget"
#include "QInputDialog"
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
    return QString("%1:%2:%3:%4:%5:%6").arg(
        QString::number(thread->Number()),
        QString::number(tp.pid),
        QString::number(tp.hook, 16),
        QString::number(tp.retn, 16),
        QString::number(tp.spl, 16),
        QString::fromWCharArray(Host::GetHookName(tp.pid, tp.hook).c_str())
    );
}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    mainWindow = this;
    processCombo = mainWindow->findChild<QComboBox*>("processCombo");
    ttCombo = mainWindow->findChild<QComboBox*>("ttCombo");
    textOutput = this->findChild<QTextBrowser*>("textOutput");

    Host::Start();
    Host::RegisterProcessAttachCallback(AddProcess);
    Host::RegisterProcessDetachCallback(RemoveProcess);
    Host::RegisterThreadCreateCallback(AddThread);
    Host::RegisterThreadRemoveCallback(RemoveThread);
    Host::Open();
}

MainWindow::~MainWindow()
{
    Host::Close();
    delete ui;
}

void AddProcess(DWORD processId)
{
    processCombo->addItem(ProcessString(processId));
}

void RemoveProcess(DWORD processId)
{
    processCombo->removeItem(processCombo->findText(ProcessString(processId)));
}

void AddThread(TextThread* thread)
{
    ttCombo->addItem(TextThreadString(thread));
    thread->RegisterOutputCallBack([](auto thread, auto data)
    {
        if (ttCombo->currentText() == TextThreadString(thread)) textOutput->append(QString::fromWCharArray(data.c_str()));
        return data + L"\r\n";
    });
}

void RemoveThread(TextThread* thread)
{
    ttCombo->removeItem(ttCombo->findText(TextThreadString(thread)));
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
    textOutput->setText(QString::fromWCharArray(Host::GetThread(index)->GetStore().c_str()));
}

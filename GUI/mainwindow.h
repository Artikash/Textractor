#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <Windows.h>
#include "../texthook/textthread.h"

namespace Ui
{
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_attachButton_clicked();
    void on_detachButton_clicked();
    void on_ttCombo_activated(int index);

private:
    Ui::MainWindow *ui;
};

void AddProcess(DWORD processId);
void RemoveProcess(DWORD processId);
void AddThread(TextThread* thread);
void RemoveThread(TextThread* thread);

#endif // MAINWINDOW_H

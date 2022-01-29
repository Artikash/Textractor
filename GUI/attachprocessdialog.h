#pragma once

#include "qtcommon.h"
#include "ui_attachprocessdialog.h"
#include <QStandardItemModel>

class AttachProcessDialog : public QDialog
{
public:
    explicit AttachProcessDialog(QWidget* parent, std::vector<std::pair<QString, HICON>> processIcons);
    QString SelectedProcess();

private:
    Ui::AttachProcessDialog ui;
    QStandardItemModel model;
    QString selectedProcess;
};

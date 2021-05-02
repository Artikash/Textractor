#include "attachtoprocessdialog.h"
#include "ui_attachtoprocessdialog.h"
#include "utils/windowshelpers.h"

#include <QStandardItemModel>
#include <algorithm>
#include <limits>

namespace
{
    QString GetNameProcessFromIndex(const QModelIndex &index, const QVector<QPair<QString, HICON>>& data)
    {
        const int row = index.row();
        return data[row].first;
    }
}

AttachToProcessDialog::AttachToProcessDialog(QWidget *parent) :
    QDialog(parent, Qt::WindowCloseButtonHint),
    ui(new Ui::AttachToProcessDialog),
    model(new QStandardItemModel(this))
{
    ui->setupUi(this);

    const QIntValidator* validator = new QIntValidator(0, INT_MAX, this);
    ui->lineEdit->setValidator(validator);
}

AttachToProcessDialog::~AttachToProcessDialog()
{
    delete ui;
}

void AttachToProcessDialog::setLabelText(const QString& text)
{
    ui->label->setText(text);
}

void AttachToProcessDialog::setData(QVector<QPair<QString, HICON>>&& newData)
{
    data = std::move(newData);
    selectedProcess.clear();
    std::sort(data.begin(), data.end(), [](const auto& left, const auto& right) {
       return left.first < right.first;
    });
    model->clear();
    for (const auto& [process, hIcon] : data)
    {
        QIcon icon = WindowsHepers::CreateQIconFromHIcon(hIcon);
        auto* item = new QStandardItem(icon, process);
        item->setEditable(false);
        model->appendRow(item);
    }
    ui->listView->setModel(model);
}

QString AttachToProcessDialog::getSelectedData()
{
    return selectedProcess.isEmpty() ? ui->lineEdit->text() : selectedProcess;
}

void AttachToProcessDialog::on_buttonBox_accepted()
{
    accept();
}

void AttachToProcessDialog::on_buttonBox_rejected()
{
    reject();
}

void AttachToProcessDialog::on_listView_doubleClicked(const QModelIndex& index)
{
    selectedProcess = GetNameProcessFromIndex(index, data);
    accept();
}

void AttachToProcessDialog::on_lineEdit_returnPressed()
{
    selectedProcess = ui->lineEdit->text();
    accept();
}

void AttachToProcessDialog::on_listView_clicked(const QModelIndex &index)
{
    selectedProcess = GetNameProcessFromIndex(index, data);
}

void AttachToProcessDialog::on_lineEdit_editingFinished()
{
     selectedProcess = ui->lineEdit->text();
}

#ifndef ATTACHTOPROCESSDIALOG_H
#define ATTACHTOPROCESSDIALOG_H

#include <QDialog>
#include <QString>
#include <QPair>
#include <QStyledItemDelegate>
#include <QVector>
#include <QtWinExtras/QtWin>

QT_BEGIN_NAMESPACE
namespace Ui {
class AttachToProcessDialog;
}
QT_END_NAMESPACE

class QStandardItemModel;
class QModelIndex;

class AttachToProcessDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AttachToProcessDialog(QWidget *parent = nullptr);
    void setData(QVector<QPair<QString, HICON>>&& newData);
    void setLabelText(const QString& text);
    QString getSelectedData();
    ~AttachToProcessDialog();

private slots:
    void on_buttonBox_accepted();

    void on_buttonBox_rejected();

    void on_listView_doubleClicked(const QModelIndex &index);

    void on_lineEdit_returnPressed();

    void on_listView_clicked(const QModelIndex &index);

    void on_lineEdit_editingFinished();

private:
    Ui::AttachToProcessDialog* ui;
    QStandardItemModel* model;
    QString selectedProcess;
    QVector<QPair<QString, HICON>> data;
};

#endif // ATTACHTOPROCESSDIALOG_H
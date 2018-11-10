#ifndef SETDIALOG_H
#define SETDIALOG_H

#include "qtcommon.h"
#include <QSpinBox>

namespace Ui
{
	class SetDialog;
}

class SetDialog : public QDialog
{
	Q_OBJECT

public:
	explicit SetDialog(QWidget* parent = nullptr);
	~SetDialog();

private slots:
	void on_buttonBox_accepted();

private:
	Ui::SetDialog* ui;
	QSpinBox* flushDelay;
	QSpinBox* maxBufferSize;
	QSpinBox* defaultCodepage;
};

#endif // SETDIALOG_H

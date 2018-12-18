#pragma once

#include "qtcommon.h"
#include <QSpinBox>

namespace Ui
{
	class SetDialog;
}

class SetDialog : public QDialog
{
public:
	explicit SetDialog(QWidget* parent = nullptr);
	~SetDialog();

private:
	Ui::SetDialog* ui;
	QSpinBox* flushDelay;
	QSpinBox* maxBufferSize;
	QSpinBox* defaultCodepage;
	bool edited = false;
};

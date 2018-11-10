#include "setdialog.h"
#include "ui_setdialog.h"
#include "defs.h"
#include "host/host.h"
#include <QSettings>

SetDialog::SetDialog(QWidget* parent) :
	QDialog(parent, Qt::WindowCloseButtonHint),
	ui(new Ui::SetDialog)
{
	ui->setupUi(this);

	QFormLayout* layout = findChild<QFormLayout*>("layout");

	auto addSpinBox = [&](QString label, int value)
	{
		auto spinbox = new QSpinBox(this);
		spinbox->setMaximum(INT_MAX);
		spinbox->setValue(value);
		layout->insertRow(0, label, spinbox);
		return spinbox;
	};
	flushDelay = addSpinBox(FLUSH_DELAY, TextThread::flushDelay);
	maxBufferSize = addSpinBox(MAX_BUFFER_SIZE, TextThread::maxBufferSize);
	defaultCodepage = addSpinBox(DEFAULT_CODEPAGE, TextThread::defaultCodepage);
}

SetDialog::~SetDialog()
{
	delete ui;
}

void SetDialog::on_buttonBox_accepted()
{
	QSettings settings(CONFIG_FILE, QSettings::IniFormat);
	settings.setValue(FLUSH_DELAY, TextThread::flushDelay = flushDelay->value());
	settings.setValue(MAX_BUFFER_SIZE, TextThread::maxBufferSize = maxBufferSize->value());
	settings.setValue(DEFAULT_CODEPAGE, TextThread::defaultCodepage = defaultCodepage->value());
	settings.sync();
}
#include "attachprocessdialog.h"
#include <QtWinExtras/QtWin>

extern const char* SELECT_PROCESS;
extern const char* ATTACH_INFO;

AttachProcessDialog::AttachProcessDialog(QWidget* parent, std::vector<std::pair<QString, HICON>> processIcons) :
	QDialog(parent, Qt::WindowCloseButtonHint),
	model(this)
{
	ui.setupUi(this);
	setWindowTitle(SELECT_PROCESS);
	ui.label->setText(ATTACH_INFO);
	ui.processList->setModel(&model);

	QPixmap transparent(100, 100);
	transparent.fill(QColor::fromRgba(0));
	for (const auto& [process, icon] : processIcons)
	{
		auto item = new QStandardItem(icon ? QIcon(QtWin::fromHICON(icon)) : transparent, process);
		item->setEditable(false);
		model.appendRow(item);
	}

	connect(ui.buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
	connect(ui.buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(ui.processList, &QListView::clicked, [this](QModelIndex index) { ui.processEdit->setText(model.item(index.row())->text()); });
	connect(ui.processList, &QListView::doubleClicked, this, &QDialog::accept);
	connect(ui.processEdit, &QLineEdit::textEdited, [this](QString process)
	{
		for (int i = 0; i < model.rowCount(); ++i) ui.processList->setRowHidden(i, !model.item(i)->text().contains(process, Qt::CaseInsensitive));
	});
	connect(ui.processEdit, &QLineEdit::returnPressed, this, &QDialog::accept);
}

QString AttachProcessDialog::SelectedProcess()
{
	return ui.processEdit->text();
}

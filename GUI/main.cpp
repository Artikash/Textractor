#include "mainwindow.h"
#include "misc.h"
#include "host/util.h"
#include <QApplication>

int main(int argc, char *argv[])
{
	QDir::setCurrent(QFileInfo(S(Util::GetModuleFilename().value())).absolutePath());

	return QApplication(argc, argv), MainWindow().show(), QApplication::exec();
}

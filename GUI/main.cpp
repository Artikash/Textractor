#include "mainwindow.h"
#include "misc.h"
#include "host/util.h"
#include <QApplication>

int main(int argc, char *argv[])
{
	QDir::setCurrent(QFileInfo(S(Util::GetModuleFilename().value())).absolutePath());

	QApplication a(argc, argv);
	MainWindow w;
	w.show();
	return a.exec();
}

#include "mainwindow.h"
#include "../texthook/host.h"
#include <QApplication>

int main(int argc, char *argv[])
{
	if (!Host::Start()) return 1;
	QApplication a(argc, argv);
	MainWindow w;
	w.show();

	return a.exec();
}

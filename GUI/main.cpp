#include "mainwindow.h"
#include "host/host.h"
#include "misc.h"
#include <sstream>
#include <QApplication>

int main(int argc, char *argv[])
{
	Host::Setup();
	QString exe = GetFullModuleName(GetCurrentProcessId());
	SetCurrentDirectoryW(exe.left(exe.lastIndexOf("\\")).toStdWString().c_str());
	QApplication a(argc, argv);
	MainWindow w;
	w.show();
	return a.exec();
}

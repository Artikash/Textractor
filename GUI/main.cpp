#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
	_CrtMemState memStates[100] = {};
	_CrtMemCheckpoint(memStates);
	{
		QApplication a(argc, argv);
		MainWindow w;
		w.show();


		a.exec();
	}
	_CrtMemCheckpoint(memStates + 1);
	if (_CrtMemDifference(memStates + 2, memStates + 0, memStates + 1))
		_CrtMemDumpStatistics(memStates + 2);
	return 0;
}

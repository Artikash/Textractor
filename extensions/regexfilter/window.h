#ifndef WINDOW_H
#define WINDOW_H

#include "common.h"
#include <QMainWindow>
#include <QString>

namespace Ui
{
	class Window;
}

class Window : public QMainWindow
{
	Q_OBJECT

public:
	explicit Window(QWidget *parent = nullptr);
	~Window();

	Ui::Window* ui;
	std::mutex m;
	std::wregex regex;

private slots:
	void on_regexInput_textEdited(const QString& regex);
};

#endif // WINDOW_H

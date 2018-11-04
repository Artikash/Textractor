#ifndef WINDOW_H
#define WINDOW_H

#include <QMainWindow>
#include <QString>
#include <regex>
#include <mutex>

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
	std::mutex locker;
	std::wregex regex;

private slots:
	void on_regexInput_textEdited(const QString& regex);
};

#endif // WINDOW_H

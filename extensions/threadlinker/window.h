#ifndef WINDOW_H
#define WINDOW_H

#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <QMainWindow>
#include <QListWidget>

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
	std::unordered_map<int64_t, std::unordered_multiset<int64_t>> linkedTextHandles;

private slots:
	void on_linkButton_clicked();
	void on_unlinkButton_clicked();

private:
	QListWidget* threadLinkList;
};

#endif // WINDOW_H

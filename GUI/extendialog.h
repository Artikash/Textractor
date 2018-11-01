#ifndef EXTENSIONS_H
#define EXTENSIONS_H

#include "qtcommon.h"
#include <shared_mutex>
#include <QDialog>
#include <QListWidget>
#include <QFile>

namespace Ui
{
	class ExtenDialog;
}

class ListRearrangeFilter : public QObject
{
	Q_OBJECT

public:
	explicit ListRearrangeFilter(QWidget* parent = nullptr);

protected:
	bool eventFilter(QObject*, QEvent* event);

signals:
	void SigRearranged();
};

class ExtenDialog : public QDialog
{
	Q_OBJECT

public:
	explicit ExtenDialog(QWidget* parent = nullptr);
	~ExtenDialog();
	static bool DispatchSentenceToExtensions(std::wstring& sentence, std::unordered_map<std::string, int64_t> miscInfo);

private slots:
	void on_addButton_clicked();
	void on_rmvButton_clicked();
	void Rearrange();

private:
	struct InfoForExtension
	{
		const char* name;
		int64_t value;
		InfoForExtension* next;
		~InfoForExtension() { if (next) delete next; };
	};
	struct Extension
	{
		QString name;
		wchar_t*(*callback)(const wchar_t*, const InfoForExtension*);
	};
	inline static std::shared_mutex extenMutex;
	inline static QVector<Extension> extensions;

	static void Load(QString extenName);
	static void Unload(QString extenName);

	void Sync();

	Ui::ExtenDialog* ui;
	QFile extenSaveFile = QFile("Extensions.txt");
	QListWidget* extenList;
	ListRearrangeFilter* filter;
};

#endif // EXTENSIONS_H

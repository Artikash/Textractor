cd Builds/RelWithDebInfo/x86;
Compress-Archive -Force -DestinationPath Textractor -Path @(
	"Textractor.exe",
	"styles",
	"platforms",
	"Qt5Core.dll",
	"Qt5Gui.dll",
	"Qt5Widgets.dll",
	"vnrhook.dll",
	"Remove Repetition.dll",
	"Copy to Clipboard.dll",
	"Bing Translate.dll",
	"Extra Newlines.dll",
	"Extensions.txt"
)

cd ../x64;
Compress-Archive -Force -DestinationPath Textractor -Path @(
	"Textractor.exe",
	"styles",
	"platforms",
	"Qt5Core.dll",
	"Qt5Gui.dll",
	"Qt5Widgets.dll",
	"vnrhook.dll",
	"Remove Repetition.dll",
	"Copy to Clipboard.dll",
	"Bing Translate.dll",
	"Extra Newlines.dll",
	"Extensions.txt"
)
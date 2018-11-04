cd Builds/RelWithDebInfo/x86;
Compress-Archive -Force -DestinationPath Textractor -Path @(
	"Textractor.exe",
	"styles",
	"platforms",
	"Qt5Core.dll",
	"Qt5Gui.dll",
	"Qt5Widgets.dll",
	"vnrhook.dll",
	"Bing Translate.dll",
	"Copy to Clipboard.dll",
	"Extra Newlines.dll",
	"Google Translate.dll",
	"Regex Filter.dll",
	"Remove Repetition.dll",
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
	"Bing Translate.dll",
	"Copy to Clipboard.dll",
	"Extra Newlines.dll",
	"Google Translate.dll",
	"Regex Filter.dll",
	"Remove Repetition.dll",
	"Extensions.txt"
)
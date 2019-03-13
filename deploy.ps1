param([string]$arch = "86", [string]$folder = "Textractor$($arch)")

Set-Location $PSScriptRoot;

$targets = @(
	"Textractor.exe",
	"TextractorCLI.exe",
	"texthook.dll",
	"Qt5Core.dll",
	"Qt5Gui.dll",
	"Qt5Widgets.dll",
	"LoaderDll.dll",
	"LocaleEmulator.dll",
	"Bing Translate.dll",
	"Copy to Clipboard.dll",
	"Extra Newlines.dll",
	"Extra Window.dll",
	"Google Translate.dll",
	"Lua.dll",
	"Regex Filter.dll",
	"Remove Repetition.dll",
	"Replacer.dll",
	"Thread Linker.dll",
	"platforms",
	"styles"
) | ForEach-Object { "builds/RelWithDebInfo_x$($arch)/$($_)" };
mkdir -Force -Verbose $folder;
Remove-Item -Force -Recurse -Verbose "$($folder)/*";
Copy-Item -Force -Recurse -Verbose -Destination $folder -Path $targets;
Compress-Archive -Force -Verbose -DestinationPath "$($folder).zip" -Path $folder;

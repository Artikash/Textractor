Set-Location "$($PSScriptRoot)/Builds";

foreach ($arch in @("86", "64")) {
	$folder = "Textractor$($arch)";
	$targets = @(
		"Textractor.exe",
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
		"Extensions.txt",
		"platforms",
		"styles"
	) | ForEach-Object { "RelWithDebInfo_x$($arch)/$($_)" };
	mkdir -Force -Verbose $folder;
	Remove-Item -Force -Recurse -Verbose "$($folder)/*";
	Copy-Item -Force -Recurse -Verbose -Destination $folder -Path $targets;
	Compress-Archive -Force -Verbose -DestinationPath $folder -Path $folder;
}

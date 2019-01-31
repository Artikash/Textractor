Set-Location $PSScriptRoot;

foreach ($arch in @("86", "64")) {
	$folder = "Textractor$($arch)";
	$targets = @(
		"Textractor.exe",
		"TextractorCLI.exe",
		"vc_redist.x$($arch).exe"
		"vnrhook.dll",
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
	Compress-Archive -Force -Verbose -DestinationPath $folder -Path $folder;
}

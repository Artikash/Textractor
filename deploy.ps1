param([string]$version)

cd $PSScriptRoot;
mkdir -Force -Verbose Builds;
cd Builds;
mkdir -Force -Verbose x86;
mkdir -Force -Verbose x64;

foreach ($language in @{
	ENGLISH="";
	SPANISH="Español";
	SIMPLIFIED_CHINESE="简体中文";
	RUSSIAN="Русский";
	TURKISH="Türkçe";
}.GetEnumerator())
{
	$folder = "Textractor-$($language.Value)-$($version)";
	mkdir -Force -Verbose $folder;
	rm -Force -Recurse -Verbose "$($folder)/*";

	$files = @(
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
	);
	cd "x86";
	cmake -G "Visual Studio 15 2017" -DTEXT_LANGUAGE="$($language.Key)" -DCMAKE_BUILD_TYPE="Release" ../..;
	&"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv" Textractor.sln /build "Release|Win32";
	cd ..;
	foreach ($file in $files)
	{
		copy -Force -Recurse -Verbose -Destination $folder -Path "Release_x86/$($file)";
	}
	cd "x64";
	cmake -G "Visual Studio 15 2017 Win64" -DTEXT_LANGUAGE="$($language.Key)" -DCMAKE_BUILD_TYPE="Release" ../..;
	&"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv" Textractor.sln /build "Release|x64";
	cd ..;
	mkdir -Force -Verbose "$($folder)/x64";
	foreach ($file in $files)
	{
		copy -Force -Recurse -Verbose -Destination "$($folder)/x64" -Path "Release_x64/$($file)";
	}
}

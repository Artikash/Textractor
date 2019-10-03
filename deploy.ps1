param([string]$version)

cd $PSScriptRoot;
mkdir -Force -Verbose Builds;
cd Builds;
mkdir -Force -Verbose x86;
mkdir -Force -Verbose x64;

foreach ($language in @{
	ENGLISH="";
	SPANISH="Spanish";
	SIMPLIFIED_CHINESE="Simplified-Chinese";
	RUSSIAN="Russian";
	TURKISH="Turkish";
	INDONESIAN="Indonesian";
	PORTUGUESE="Portuguese";
	THAI="Thai";
	KOREAN="Korean";
}.GetEnumerator())
{
	$folder = "Textractor-$($language.Value)-$version";
	rm -Force -Recurse -Verbose $folder;
	mkdir -Force -Verbose $folder;

	foreach ($arch in @("x86", "x64"))
	{
		cd $arch;
		$VS_arch = if ($arch -eq "x86") {"Win32"} else {"x64"};
		cmake -G "Visual Studio 16 2019" -A"$VS_arch" -DVERSION="$version" -DTEXT_LANGUAGE="$($language.Key)" -DCMAKE_BUILD_TYPE="Release" ../..;
		&"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv" Textractor.sln /build "Release|$VS_arch";
		cd ..;
		mkdir -Force -Verbose "$folder/$arch";
		foreach ($file in @(
			"Textractor.exe",
			"TextractorCLI.exe",
			"texthook.dll",
			"Bing Translate.dll",
			"Copy to Clipboard.dll",
			"Extra Newlines.dll",
			"Extra Window.dll",
			"Google Translate.dll",
			"Lua.dll",
			"Regex Filter.dll",
			"Remove Repeated Characters.dll",
			"Remove Repeated Phrases.dll",
			"Remove Repeated Phrases 2.dll",
			"Remove 30 Repeated Sentences.dll",
			"Replacer.dll",
			"Thread Linker.dll"
		))
		{
			copy -Force -Recurse -Verbose -Destination "$folder/$arch" -Path "Release_$arch/$file";
		}
	}
}

rm -Force -Recurse -Verbose "Runtime";
mkdir -Force -Verbose "Runtime";
foreach ($arch in @("x86", "x64"))
{
	mkdir -Force -Verbose "Runtime/$arch";
	foreach ($file in @(
		"LoaderDll.dll",
		"LocaleEmulator.dll",
		"Qt5Core.dll",
		"Qt5Gui.dll",
		"Qt5Widgets.dll",
		"platforms",
		"styles"
	))
	{
		copy -Force -Recurse -Verbose -Destination "Runtime/$arch/$file" -Path "Release_$arch/$file";
	}
}

rm -Force -Recurse -Verbose "Textractor";
mkdir -Force -Verbose "Textractor";
copy -Force -Recurse -Verbose -Destination "Textractor" -Path @("Runtime/*", "Textractor--$version/*");

cd ..
&"C:\Program Files (x86)\Inno Setup 6\iscc.exe" -DVERSION="$version" installer.iss

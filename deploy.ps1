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
}.GetEnumerator())
{
	$folder = "Textractor-$($language.Value)-$version";
	mkdir -Force -Verbose $folder;
	rm -Force -Recurse -Verbose "$folder/*";

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
			"Remove 30 Repeated Sentences.dll",
			"Replacer.dll",
			"Thread Linker.dll"
		))
		{
			copy -Force -Recurse -Verbose -Destination "$folder/$arch" -Path "Release_$arch/$file";
		}
	}
}

mkdir -Force -Verbose "Runtime";
rm -Force -Recurse -Verbose "Runtime/*";
foreach ($file in @(
	"Qt5Core.dll",
	"Qt5Gui.dll",
	"Qt5Widgets.dll",
	"LoaderDll.dll",
	"LocaleEmulator.dll",
	"platforms",
	"styles"
))
{
	foreach ($arch in @("x86", "x64"))
	{
		mkdir -Force -Verbose "Runtime/$arch";
		copy -Force -Recurse -Verbose -Destination "Runtime/$arch/$file" -Path "Release_$arch/$file";
	}
}

cd ..
&"C:\Program Files (x86)\Inno Setup 6\iscc.exe" -DVERSION="$version" installer.iss

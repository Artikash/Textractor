# Textractor

![How it looks](screenshot.png)

[English](README.md) ● [Español](README_ES.md) ● [简体中文](README_SC.md) ● [Русский](README_RU.md) ● [한국어](README_KR.md) ● [ภาษาไทย](README_TH.md) ● [Français](README_FR.md) ● [Italiano](README_IT.md) ● [日本語](README_JP.md) ● [Bahasa](README_ID.md) ● [Português](README_PT.md)

**Textractor** (a.k.a. NextHooker) is an open-source x86/x64 video game text hooker for Windows/Wine based off of [ITHVNR](https://web.archive.org/web/20160202084144/http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine).<br>
Watch the [tutorial video](https://tinyurl.com/textractor-tutorial) for a quick rundown on using it.

## Download

Official stable releases of Textractor can be found [here](https://github.com/Artikash/Textractor/releases).<br>
The last release of ITHVNR can be found [here](https://drive.google.com/open?id=13aHF4uIXWn-3YML_k2YCDWhtGgn5-tnO).<br>
Experimental builds of Textractor (with debug info) from the latest source can be found [here](https://ci.appveyor.com/project/Artikash/textractor/history) in the 'Artifacts' section of each job.<br>
Try running vcredist if you get an error when starting Textractor or if nothing happens when you try attaching to a game.

## Features

- Highly extensible and customizable
- Auto hook many game engines (including some not supported by VNR!)
- Hook text using /H "hook" codes (most AGTH codes supported)
- Automatically search for possible hook codes

## Support

Please let me know of any bugs, games that Textractor has trouble hooking, feature requests, or other suggestions.<br>
If you have trouble hooking a game please email me a place where I can freely download it, or gift it to me on [Steam](https://steamcommunity.com/profiles/76561198097566313/).

## Extensions

See my [Example Extension project](https://github.com/Artikash/ExampleExtension) to see how to build an extension.<br>
See the extensions folder for examples of what extensions can do. 

## Contributing

All contributions are appreciated! Please email (no, I'm not busy!) me at akashmozumdar@gmail.com if you have any questions about the codebase.<br>
You should use the standard process of making a pull request (fork, branch, commit changes, make PR from your branch to my master).<br>
Contributing a translation is easy: just translate the strings in text.cpp as well as this README and the subtitles of the tutorial video.

## Compiling

Before compiling Textractor, you should get Qt version 5.13 and Visual Studio with CMake support. You should then be able to just open the source folder in Visual Studio and build.

## Project Architecture

The host (see GUI/host folder) injects texthook.dll (created from the texthook folder) into the target process and connects to it via 2 pipe files.<br>
Host writes to hostPipe, texthook writes to hookPipe.<br>
texthook waits for the pipe to be connected, then injects a few instructions into any text outputting functions (e.g. TextOut, GetGlyphOutline) that cause their input to be sent through the pipe.<br>
Additional information about hooks is exchanged via shared memory.<br>
The text that the host receives through the pipe is then processed a little before being dispatched back to the GUI.<br>
Finally, the GUI dispatches the text to extensions before displaying it.

## [Developers](CREDITS.md)

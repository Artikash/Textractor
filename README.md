# Textractor

[日本語](https://github.com/Artikash/Textractor/blob/master/README_JP.md)

## Overview

**Textractor** (a.k.a. NextHooker) is an open-source x86/x64 text hooker for Windows/Wine based off of [ITHVNR](http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine).

![How it looks](https://media.discordapp.net/attachments/330538905072041994/486629608456847360/unknown.png?width=1083&height=353)

## Downloads

Releases of Textractor can be found [here](https://github.com/Artikash/Textractor/releases).

Previous releases of ITHVNR can be found [here](https://github.com/mireado/ITHVNR/releases).

## Features

- Highly extensible
- x64 supported (x64 version only works with x64 programs)
- Hook text using /H "hook" codes (most AGTH codes supported)
- Directly read text using /R "read" codes ([Guide](https://www.youtube.com/watch?v=AcEgjCoww5w))
- Auto hook many game engines (including some not supported by VNR!)

## Extensions

See my [Example Extension project](https://github.com/Artikash/ExampleExtension) to see how to build an extension.<br>
See the extensions folder and my [Extensions project](https://github.com/Artikash/Extensions) for examples of what extensions can do. 

## Compiling

Before compiling *Textractor*, you should get Visual Studio with CMake and ATL support, as well as Qt version 5.11<br>
You should then be able to simply open the folder in Visual Studio, and build. Run Build/Textractor.exe.

## Project Architecture

The host (see GUI/host folder) injects vnrhook.dll (created from the vnrhook folder) into the target process and connects to it via 2 pipe files.<br>
Host writes to hostPipe, vnrhook writes to hookPipe.<br>
vnrhook waits for the pipe to be connected, then injects a few instructions into any text outputting functions (e.g. TextOut, GetGlyphOutline) that cause their input to be sent through the pipe.<br>
Additional information about hooks is shared through a file view (a.k.a. section object) that is mapped to a reference to the TextHook class.<br>
The text that the host receives through the pipe is then processed a little before being dispatched back to the GUI and displayed.

## Contributing

All contributions are appreciated! Please email (no, I'm not busy!) me at akashmozumdar@gmail.com if you have any questions about the codebase.<br>
You should use the standard process of making a pull request (fork, branch, commit changes, make PR from your branch to my master).

## Developers

- Textractor creation/updating by [Me](https://github.com/Artikash) and [DoumanAsh](https://github.com/DoumanAsh)
- ITHVNR updating by [mireado](https://github.com/mireado) and [Eguni](https://github.com/Eguni)
- ITHVNR new GUI & VNR engine migration by [Stomp](http://www.hongfire.com/forum/member/325894-stomp)
- VNR engine making by [jichi](https://archive.is/prJwr)
- ITH updating by [Andys](https://github.com/AndyScull)
- ITH originally made by [kaosu](http://www.hongfire.com/forum/member/562651-kaosu)
- MinHook library made by [TsudaKageyu](https://github.com/TsudaKageyu)

## Special Thanks

- Everybody adding issues!

# NextHooker



## Overview

*NextHooker* is an open-source x86/x64 text hooker for Windows.

Basically, GUI text hooker based on [Stomp](http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine)'s ITHVNR.

## Downloads

Releases of NextHooker can be found [here](https://github.com/Artikash/NextHooker/releases)

Previous releases of ITHVNR can be found [here](https://github.com/mireado/ITHVNR/releases).

## Features

- Open-source
- x64 supported
- Hook text (most AGTH hook codes supported)
- Directly read text ([Guide](https://www.youtube.com/watch?v=AcEgjCoww5w))
- Auto hook many engines (including some not supported by VNR!)
- Extensions

## Extensions

See my [Example Extension project](https://github.com/Artikash/ExampleExtension) to see how to build an extension.

## Compiling

Before compiling *NextHooker*, you should get Visual Studio with CMake and ATL support, as well as Qt version 5.11<br>
You should then be able to simply open the folder in Visual Studio, and build. Run Build/NextHooker.exe

## Project Architecture

The GUI links to vnrhost.dll (created from the texthook folder) which injects vnrhook.dll (created from the vnrhook folder) into the target process and connects to it via 2 pipe files.<br>
vnrhost writes to hostPipe, vnrhook writes to hookPipe (duh?)<br>
vnrhook waits for the pipe to be connected, then injects a few instructions into any text outputting functions (e.g. TextOut, GetGlyphOutline) that cause their input to be sent through the pipe.<br>
Additional information about hooks is shared through a file view (a.k.a. section object) that is mapped to a reference to the Hook class.<br>
The text that vnrhost receives through the pipe is then processed a little before being dispatched back to the GUI and displayed.

## Contributing

All contributions are appreciated! Please email (no, I'm not busy!) me at akashmozumdar@gmail.com if you have any questions about the codebase; I know it's messy and undercommented.<br>
You should use the standard process of making a pull request (fork, branch, commit changes, make PR from your branch to my master).

## License

GPL v3

## Developers

- Copyright (C) 2010-2012  [kaosu](http://www.hongfire.com/forum/member/562651-kaosu)
- VNR engine making by [jichi](https://archive.is/prJwr)
- ITH updating by [Andys](https://github.com/AndyScull)
- ITHVNR new GUI & VNR engine migration by [Stomp](http://www.hongfire.com/forum/member/325894-stomp)
- ITHVNR updating by [mireado](https://github.com/mireado) and [Eguni](https://github.com/Eguni)
- NextHooker creation/updating by [Me](https://github.com/Artikash) and [DoumanAsh](https://github.com/DoumanAsh)

## Special Thanks

- Everybody adding issues!

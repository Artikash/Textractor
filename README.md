# NextHooker



## Overview

*NextHooker* is an open-source x32~~/x64~~ text hooker for Windows.

Basically, GUI text hooker based on [Stomp](http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine)'s ITHVNR.

## Extensions

See my [Example Extension project](https://github.com/Artikash/ExampleExtension) to see how to build an extension.

To use an extension, simply rename the extension dll file to ```{NUMBER}_nexthooker_extension.dll``` and copy into the NextVNR folder. 

Extensions are called in order by the number they are prefixed with.

## Downloads

Releases of *NextHooker* can be found [here](https://github.com/Artikash/NextHooker/releases)

Previous releases of *ITHVNR* can be found [here](https://github.com/mireado/ITHVNR/releases).

## Features

- Open-source
- Hook text (AGTH hook codes supported)
- Extensions (New!)

## License

GPL v3

## Developers

- Copyright (C) 2010-2012  [kaosu](qiupf2000@gmail.com)
- VNR engine making by [jichi](http://sakuradite.com/topic)
- ITH updating by [Andys](http://www.hongfire.com/forum/member/126633-andys)
- ITHVNR new GUI & VNR engine migration by [Stomp](http://www.hongfire.com/forum/member/325894-stomp)
- ITHVNR updating by [mireado](http://blog.naver.com/mireado) and [Eguni](https://github.com/Eguni)
- Korean GUI by [IJEMIN](https://github.com/IJEMIN)

## Special Thanks

- Everybody adding issues!

## Compiling

Before compiling *NextHooker*, You should get CMake, [Windows Driver Kit 7.1](http://www.microsoft.com/en-us/download/details.aspx?id=11800), and Visual Studio.

## Project Architecture

The GUI links to vnrhost.dll (created from the texthook folder) which injects vnrhook.dll (created from the vnrhook folder) into the target process and connects to it via 2 pipe files.<br>
vnrhost writes to hostPipe, vnrhook writes to hookPipe (duh?)<br>
vnrhook waits for the pipe to be connected, then injects a few instructions into any text outputting functions (e.g. TextOut, GetGlyphOutline) that cause their input to be sent through the pipe.<br>
Additional information about hooks is shared through a section object that is mapped to a reference to the Hook class.<br>
The text that vnrhost receives through the pipe is then processed a little before being dispatched back to the GUI and displayed.

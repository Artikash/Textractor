# NextHooker



## Overview

*NextHooker* is an open-source x86~~ text hooker for Windows.

Basically, GUI text hooker based on [Stomp](http://www.hongfire.com/forum/showthread.php/438331-ITHVNR-ITH-with-the-VNR-engine)'s ITHVNR.

## Extensions

See my [Example Extension project](https://github.com/Artikash/ExampleExtension) to see how to build an extension.

To use an extension, simply rename the extension dll file to ```{NUMBER}_{NAME}_nexthooker_extension.dll``` and copy into the NextHooker folder. 

Extensions are called in order by the number they are prefixed with.

## Downloads

Releases of *NextHooker* can be found [here](https://github.com/Artikash/NextHooker/releases)

Previous releases of *ITHVNR* can be found [here](https://github.com/mireado/ITHVNR/releases).

## Features

- Open-source
- Hook text (most AGTH hook codes supported)
- Auto hook many engines (including some not supported by VNR!)
- Extensions (New!)

## License

GPL v3

## Developers

- Copyright (C) 2010-2012  [kaosu](http://www.hongfire.com/forum/member/562651-kaosu)
- VNR engine making by [jichi](http://sakuradite.com/topic)
- ITH updating by [Andys](https://github.com/AndyScull)
- ITHVNR new GUI & VNR engine migration by [Stomp](http://www.hongfire.com/forum/member/325894-stomp)
- ITHVNR updating by [mireado](https://github.com/mireado) and [Eguni](https://github.com/Eguni)

## Special Thanks

- Everybody adding issues!

## Compiling

Before compiling *NextHooker*, you should get Visual Studio with CMake, ATL, and .NET 4.6.<br>
You should first compile all the CMake projects, then compile the *GUI* solution.

## Project Architecture

The GUI links to vnrhost.dll (created from the texthook folder) which injects vnrhook.dll (created from the vnrhook folder) into the target process and connects to it via 2 pipe files.<br>
vnrhost writes to hostPipe, vnrhook writes to hookPipe (duh?)<br>
vnrhook waits for the pipe to be connected, then injects a few instructions into any text outputting functions (e.g. TextOut, GetGlyphOutline) that cause their input to be sent through the pipe.<br>
Additional information about hooks is shared through a file view (a.k.a. section object) that is mapped to a reference to the Hook class.<br>
The text that vnrhost receives through the pipe is then processed a little before being dispatched back to the GUI and displayed.
